"""
analyzer/pcap_analyzer.py
--------------------------
Offline PCAP analyzer for captures produced by the ESP32 firmware.

Parses 802.11 frames, extracts AP/client metadata, computes per-channel
statistics, and exports summary reports.

Usage
-----
    python analyzer/pcap_analyzer.py --file captures/sample.pcap
    python analyzer/pcap_analyzer.py --file captures/sample.pcap --export csv
    python analyzer/pcap_analyzer.py --file captures/sample.pcap --plot
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
    from scapy.layers.dot11 import Dot11AssoReq, Dot11Auth
except ImportError:
    print("[ERROR] scapy not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("[ERROR] pandas not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False


console = Console() if RICH else None


# ── helpers ──────────────────────────────────────────────────────────────────

def _mac(addr: str) -> str:
    """Normalise MAC address to uppercase colon-separated format."""
    return addr.upper() if addr else "??:??:??:??:??:??"


def _channel_from_elt(packet) -> int | None:
    """Extract channel number from Dot11Elt DS Parameter Set (ID=3)."""
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and len(elt.info) >= 1:
            return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None
    return None


def _rsn_from_elt(packet) -> str:
    """Detect encryption type from RSN (ID=48) or WPA vendor (ID=221) elements."""
    elt = packet.getlayer(Dot11Elt)
    has_rsn = False
    has_wpa = False
    while elt:
        if elt.ID == 48:
            has_rsn = True
        if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
            has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None
    if has_rsn:
        return "WPA2"
    if has_wpa:
        return "WPA"
    return "OPEN/WEP"


# ── core parser ──────────────────────────────────────────────────────────────

def parse_pcap(path: str) -> dict:
    """
    Parse a PCAP file and return a structured summary dict with keys:
        'aps'      – list of AccessPoint dicts
        'clients'  – list of Client dicts
        'frames'   – total frame count
        'duration' – capture duration in seconds (if timestamps available)
        'file'     – source file path
    """
    packets = rdpcap(path)
    aps: dict[str, dict] = {}      # bssid → AP info
    clients: dict[str, dict] = {}  # mac   → client info
    frame_count = len(packets)
    timestamps = []

    for pkt in packets:
        if pkt.haslayer(Dot11):
            ts = float(pkt.time)
            timestamps.append(ts)

            dot11 = pkt.getlayer(Dot11)

            # ── Beacon / Probe Response → AP info ───────────────────────────
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                bssid = _mac(dot11.addr3)
                ssid_elt = pkt.getlayer(Dot11Elt)
                ssid = ssid_elt.info.decode("utf-8", errors="replace") if ssid_elt else "<hidden>"
                channel = _channel_from_elt(pkt)
                enc = _rsn_from_elt(pkt)

                if bssid not in aps:
                    aps[bssid] = {
                        "bssid":    bssid,
                        "ssid":     ssid,
                        "channel":  channel,
                        "enc":      enc,
                        "beacons":  0,
                        "first_seen": ts,
                        "last_seen":  ts,
                    }
                aps[bssid]["beacons"] += 1
                aps[bssid]["last_seen"] = max(aps[bssid]["last_seen"], ts)

            # ── Data / Management frames → client activity ──────────────────
            if dot11.type in (0, 2):  # management or data
                src = _mac(dot11.addr2)
                dst = _mac(dot11.addr1)
                bssid_ref = _mac(dot11.addr3)

                for mac in (src, dst):
                    if mac and not mac.startswith("FF:FF"):
                        if mac not in clients:
                            clients[mac] = {
                                "mac":       mac,
                                "bssid_ref": bssid_ref,
                                "frames":    0,
                                "first_seen": ts,
                                "last_seen":  ts,
                            }
                        clients[mac]["frames"] += 1
                        clients[mac]["last_seen"] = max(clients[mac]["last_seen"], ts)

    duration = (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 0.0

    return {
        "file":     path,
        "frames":   frame_count,
        "duration": round(duration, 2),
        "aps":      list(aps.values()),
        "clients":  list(clients.values()),
    }


# ── display ──────────────────────────────────────────────────────────────────

def print_summary(result: dict) -> None:
    """Pretty-print the analysis summary to the terminal."""
    if RICH:
        _print_rich(result)
    else:
        _print_plain(result)


def _print_rich(result: dict) -> None:
    console.print(Panel.fit(
        f"[bold cyan]File:[/] {result['file']}\n"
        f"[bold cyan]Total frames:[/] {result['frames']}\n"
        f"[bold cyan]Capture duration:[/] {result['duration']}s\n"
        f"[bold cyan]Access Points found:[/] {len(result['aps'])}\n"
        f"[bold cyan]Client MACs seen:[/] {len(result['clients'])}",
        title="📡 PCAP Analysis Summary",
        border_style="cyan",
    ))

    # AP table
    ap_table = Table(title="Access Points", box=box.ROUNDED, border_style="blue")
    for col in ("BSSID", "SSID", "Channel", "Encryption", "Beacons"):
        ap_table.add_column(col, style="white")
    for ap in sorted(result["aps"], key=lambda x: x["channel"] or 99):
        ap_table.add_row(
            ap["bssid"],
            ap["ssid"][:32],
            str(ap["channel"] or "?"),
            ap["enc"],
            str(ap["beacons"]),
        )
    console.print(ap_table)

    # Client table (top 20 by frame count)
    cli_table = Table(title="Active Clients (top 20)", box=box.ROUNDED, border_style="magenta")
    for col in ("MAC", "Frames", "Associated BSSID"):
        cli_table.add_column(col, style="white")
    for c in sorted(result["clients"], key=lambda x: x["frames"], reverse=True)[:20]:
        cli_table.add_row(c["mac"], str(c["frames"]), c["bssid_ref"])
    console.print(cli_table)


def _print_plain(result: dict) -> None:
    print(f"\n=== PCAP Analysis Summary ===")
    print(f"File          : {result['file']}")
    print(f"Total frames  : {result['frames']}")
    print(f"Duration      : {result['duration']}s")
    print(f"Access Points : {len(result['aps'])}")
    print(f"Client MACs   : {len(result['clients'])}\n")
    print(f"{'BSSID':<20} {'SSID':<32} {'Ch':>3} {'Enc':<8} {'Beacons':>7}")
    print("-" * 75)
    for ap in sorted(result["aps"], key=lambda x: x["channel"] or 99):
        print(f"{ap['bssid']:<20} {ap['ssid'][:32]:<32} {str(ap['channel'] or '?'):>3} "
              f"{ap['enc']:<8} {ap['beacons']:>7}")


# ── export ────────────────────────────────────────────────────────────────────

def export_csv(result: dict, out_dir: str = "reports") -> None:
    """Export AP and client tables as CSV files."""
    os.makedirs(out_dir, exist_ok=True)
    stem = Path(result["file"]).stem
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")

    ap_path  = os.path.join(out_dir, f"{stem}_aps_{ts}.csv")
    cli_path = os.path.join(out_dir, f"{stem}_clients_{ts}.csv")

    pd.DataFrame(result["aps"]).to_csv(ap_path, index=False)
    pd.DataFrame(result["clients"]).to_csv(cli_path, index=False)

    print(f"[export] APs     → {ap_path}")
    print(f"[export] Clients → {cli_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Offline 802.11 PCAP analyzer for ESP32 captures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer/pcap_analyzer.py --file captures/sample.pcap
  python analyzer/pcap_analyzer.py --file captures/sample.pcap --export csv
  python analyzer/pcap_analyzer.py --file captures/sample.pcap --plot
        """,
    )
    parser.add_argument("--file",   required=True, help="Path to .pcap or .pcapng file")
    parser.add_argument("--export", choices=["csv"], help="Export results to file")
    parser.add_argument("--plot",   action="store_true", help="Generate channel utilisation plot")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)

    print(f"[*] Loading {args.file} …")
    result = parse_pcap(args.file)
    print_summary(result)

    if args.export == "csv":
        export_csv(result)

    if args.plot:
        try:
            from analyzer.visualizer import plot_channel_utilization
            plot_channel_utilization(result)
        except ImportError:
            print("[WARN] matplotlib not available — skipping plot")


if __name__ == "__main__":
    main()
