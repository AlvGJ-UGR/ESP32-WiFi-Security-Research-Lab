"""
wireshark_export.py
-------------------
Feeds ESP32 captures directly into Wireshark for live analysis.

Three methods supported:

  1. PIPE (Linux/macOS) — creates a named FIFO pipe and streams PCAP
     frames from the ESP32 HTTP endpoint into Wireshark in real time.

  2. STDOUT (Linux/macOS/Windows) — writes a valid PCAP stream to stdout,
     which Wireshark can read with: wireshark -k -i -

  3. FILE (all platforms) — polls the ESP32 HTTP endpoint periodically,
     saves the capture to a .pcap file, and opens it in Wireshark.

Usage:
    # Method 1 — named pipe (recommended on Linux/macOS)
    python analyzer/wireshark_export.py --mode pipe --url http://192.168.4.1/api/pcap/download

    # Method 2 — stdout pipe into Wireshark
    python analyzer/wireshark_export.py --mode stdout --url http://192.168.4.1/api/pcap/download | wireshark -k -i -

    # Method 3 — file polling (works everywhere)
    python analyzer/wireshark_export.py --mode file --url http://192.168.4.1/api/pcap/download --interval 10

    # Offline: open an existing .pcap in Wireshark
    python analyzer/wireshark_export.py --open capture.pcap
"""

import os
import sys
import time
import struct
import signal
import argparse
import tempfile
import subprocess
import urllib.request
from pathlib import Path


# ─────────────────────────────────────────────────────────────────
# PCAP constants
# ─────────────────────────────────────────────────────────────────

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,   # magic number (little-endian, microseconds)
    2,            # major version
    4,            # minor version
    0,            # timezone offset
    0,            # timestamp accuracy
    65535,        # snapshot length
    127,          # link type: IEEE 802.11 with radiotap
)


# ─────────────────────────────────────────────────────────────────
# Wireshark detection
# ─────────────────────────────────────────────────────────────────

def _find_wireshark() -> str | None:
    """Return the path to the Wireshark executable, or None if not found."""
    candidates = [
        "wireshark",
        "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
    ]
    for path in candidates:
        try:
            subprocess.run(
                [path, "--version"],
                capture_output=True, timeout=3
            )
            return path
        except Exception:
            continue
    return None


def _open_in_wireshark(filepath: str, wireshark: str | None = None) -> None:
    ws = wireshark or _find_wireshark()
    if not ws:
        print("[!] Wireshark not found. Open the file manually:")
        print(f"    {filepath}")
        return
    print(f"[*] Opening {filepath} in Wireshark ...")
    subprocess.Popen([ws, filepath])


# ─────────────────────────────────────────────────────────────────
# ESP32 HTTP fetch
# ─────────────────────────────────────────────────────────────────

def _fetch_pcap(url: str, timeout: int = 10) -> bytes | None:
    """Download the current PCAP from the ESP32 HTTP interface."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        print(f"[!] Fetch failed: {e}")
        return None


def _validate_pcap(data: bytes) -> bool:
    """Check that the data starts with a valid PCAP magic number."""
    if len(data) < 4:
        return False
    magic = struct.unpack("<I", data[:4])[0]
    return magic in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D)


# ─────────────────────────────────────────────────────────────────
# Mode 1: Named pipe
# ─────────────────────────────────────────────────────────────────

def mode_pipe(url: str, interval: int, wireshark_path: str | None) -> None:
    """
    Create a FIFO named pipe and stream PCAP data into Wireshark.
    Wireshark reads from the pipe as if it were a live capture interface.
    """
    if sys.platform == "win32":
        print("[!] Named pipe mode is not supported on Windows.")
        print("    Use --mode file or --mode stdout instead.")
        sys.exit(1)

    pipe_path = Path(tempfile.gettempdir()) / "esp32_capture.pcap"

    if pipe_path.exists():
        pipe_path.unlink()

    os.mkfifo(str(pipe_path))
    print(f"[*] FIFO pipe created at: {pipe_path}")

    # Launch Wireshark pointing at the pipe
    ws = wireshark_path or _find_wireshark()
    if ws:
        print(f"[*] Launching Wireshark ...")
        subprocess.Popen([ws, "-k", "-i", str(pipe_path)])
        time.sleep(2)   # Give Wireshark time to open the pipe
    else:
        print(f"[!] Start Wireshark manually and open: {pipe_path}")
        print("    File → Open → select the pipe path above")

    print(f"[*] Polling ESP32 at {url} every {interval}s ...")
    print(f"    Press Ctrl+C to stop.\n")

    def _cleanup(sig, frame):
        print("\n[*] Stopping ...")
        try:
            pipe_path.unlink()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    try:
        with open(str(pipe_path), "wb") as pipe:
            # Write global PCAP header once
            pipe.write(PCAP_GLOBAL_HEADER)
            pipe.flush()

            seen_frames = 0

            while True:
                pcap_data = _fetch_pcap(url)
                if pcap_data and _validate_pcap(pcap_data):
                    # Skip global header (24 bytes) and extract record blocks
                    offset = 24
                    new_frames = 0
                    frame_idx  = 0
                    while offset + 16 <= len(pcap_data):
                        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
                            "<IIII", pcap_data, offset
                        )
                        record_end = offset + 16 + incl_len
                        if record_end > len(pcap_data):
                            break
                        if frame_idx >= seen_frames:
                            # Write new record to pipe
                            pipe.write(pcap_data[offset:record_end])
                            new_frames += 1
                        frame_idx += 1
                        offset = record_end
                    pipe.flush()
                    seen_frames = frame_idx
                    if new_frames:
                        print(f"[+] Streamed {new_frames} new frames "
                              f"(total: {seen_frames})")
                else:
                    print(f"[!] No valid PCAP data from ESP32")

                time.sleep(interval)
    finally:
        try:
            pipe_path.unlink()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────
# Mode 2: stdout
# ─────────────────────────────────────────────────────────────────

def mode_stdout(url: str, interval: int) -> None:
    """
    Write a continuous PCAP stream to stdout.
    Pipe directly into Wireshark:
        python wireshark_export.py --mode stdout --url ... | wireshark -k -i -
    """
    out = sys.stdout.buffer
    out.write(PCAP_GLOBAL_HEADER)
    out.flush()

    seen_frames = 0
    print("[*] Streaming to stdout. Pipe to Wireshark with: | wireshark -k -i -",
          file=sys.stderr)

    try:
        while True:
            pcap_data = _fetch_pcap(url)
            if pcap_data and _validate_pcap(pcap_data):
                offset    = 24
                frame_idx = 0
                while offset + 16 <= len(pcap_data):
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
                        "<IIII", pcap_data, offset
                    )
                    record_end = offset + 16 + incl_len
                    if record_end > len(pcap_data):
                        break
                    if frame_idx >= seen_frames:
                        out.write(pcap_data[offset:record_end])
                    frame_idx += 1
                    offset = record_end
                out.flush()
                seen_frames = frame_idx
            time.sleep(interval)
    except BrokenPipeError:
        pass   # Wireshark closed — normal exit


# ─────────────────────────────────────────────────────────────────
# Mode 3: file polling
# ─────────────────────────────────────────────────────────────────

def mode_file(url: str, interval: int, output_dir: str,
              wireshark_path: str | None, auto_open: bool) -> None:
    """
    Poll the ESP32 HTTP endpoint, save captures to timestamped files,
    and optionally open each one in Wireshark automatically.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] File polling mode — saving captures to: {out_dir}")
    print(f"[*] Polling every {interval}s. Press Ctrl+C to stop.\n")

    run = 0
    try:
        while True:
            run += 1
            ts       = time.strftime("%Y%m%d_%H%M%S")
            out_path = out_dir / f"capture_{ts}.pcap"

            print(f"[{run}] Fetching from {url} ...")
            pcap_data = _fetch_pcap(url)

            if pcap_data and _validate_pcap(pcap_data):
                with open(out_path, "wb") as f:
                    f.write(pcap_data)

                size_kb = len(pcap_data) / 1024
                # Count frames
                frame_count = 0
                offset = 24
                while offset + 16 <= len(pcap_data):
                    _, _, incl_len, _ = struct.unpack_from("<IIII", pcap_data, offset)
                    offset += 16 + incl_len
                    frame_count += 1

                print(f"    ✓ Saved {frame_count} frames ({size_kb:.1f} KB) → {out_path}")

                if auto_open:
                    _open_in_wireshark(str(out_path), wireshark_path)
            else:
                print(f"    ✗ No valid PCAP received")

            if interval > 0:
                time.sleep(interval)
            else:
                break   # --interval 0 = single shot
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stream ESP32 captures into Wireshark.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--mode", choices=["pipe", "stdout", "file"],
                        default="file",
                        help="Streaming mode (default: file)")
    parser.add_argument("--url",
                        default="http://192.168.4.1/api/pcap/download",
                        help="ESP32 PCAP download endpoint")
    parser.add_argument("--interval", type=int, default=10,
                        help="Poll interval in seconds (default: 10). "
                             "Use 0 for a single download.")
    parser.add_argument("--output-dir", default="captures",
                        help="Directory for saved captures (file mode, default: captures/)")
    parser.add_argument("--wireshark", default=None,
                        help="Path to Wireshark executable (auto-detected if omitted)")
    parser.add_argument("--no-open", action="store_true",
                        help="Don't automatically open captures in Wireshark (file mode)")
    parser.add_argument("--open", metavar="FILE",
                        help="Open an existing .pcap file in Wireshark and exit")

    args = parser.parse_args()

    if args.open:
        _open_in_wireshark(args.open, args.wireshark)
        return

    print(f"\n  ESP32 → Wireshark Live Export")
    print(f"  Mode     : {args.mode}")
    print(f"  Endpoint : {args.url}")
    print(f"  Interval : {args.interval}s\n")

    ws = args.wireshark or _find_wireshark()
    if ws:
        print(f"[*] Wireshark found: {ws}")
    else:
        print("[!] Wireshark not found in PATH. Install from https://www.wireshark.org/")
        if args.mode in ("pipe",):
            sys.exit(1)

    if args.mode == "pipe":
        mode_pipe(args.url, args.interval, ws)
    elif args.mode == "stdout":
        mode_stdout(args.url, args.interval)
    else:
        mode_file(args.url, args.interval, args.output_dir,
                  ws, auto_open=not args.no_open)


if __name__ == "__main__":
    main()
