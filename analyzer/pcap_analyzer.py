"""
analyzer/pcap_analyzer.py
--------------------------
Offline PCAP analyzer for captures produced by the ESP32 firmware.

Parses 802.11 frames, extracts AP/client metadata, computes per-channel
statistics, and exports summary reports.

Usage
-----
    python analyzer/pcap_analyzer.py --file captures/sample.pcap
    python analyzer/pcap_analyzer.py --file captures/sample.pcap --export csv json
    python analyzer/pcap_analyzer.py --file captures/sample.pcap --plot
    python analyzer/pcap_analyzer.py --dir captures/ --export csv
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterator

# ── optional dependencies ─────────────────────────────────────────────────────

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
    from scapy.layers.dot11 import Dot11AssoReq, Dot11Auth
except ImportError:
    print("[ERROR] scapy not installed. Run: pip install scapy", file=sys.stderr)
    sys.exit(1)

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
    from rich import box
    RICH = True
except ImportError:
    RICH = False

# ── logging setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

console: "Console | None" = Console() if RICH else None  # type: ignore[assignment]

# ── constants ─────────────────────────────────────────────────────────────────

DOT11_ELT_SSID    = 0
DOT11_ELT_DS      = 3    # DS Parameter Set → channel
DOT11_ELT_RSN     = 48   # RSN → WPA2/WPA3
DOT11_ELT_VENDOR  = 221  # Vendor Specific (WPA)
WPA_OUI           = b"\x00\x50\xf2\x01"
BROADCAST_MAC     = "FF:FF:FF:FF:FF:FF"
UNKNOWN_MAC       = "??:??:??:??:??:??"
MAX_CLIENTS_SHOWN = 20
PCAP_EXTENSIONS   = {".pcap", ".pcapng", ".cap"}


# ── data models ───────────────────────────────────────────────────────────────

@dataclass
class AccessPoint:
    bssid:      str
    ssid:       str
    channel:    int | None
    enc:        str
    beacons:    int         = 0
    first_seen: float       = 0.0
    last_seen:  float       = 0.0

    @property
    def active_seconds(self) -> float:
        return round(self.last_seen - self.first_seen, 2)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["active_seconds"] = self.active_seconds
        return d


@dataclass
class Client:
    mac:        str
    bssid_ref:  str
    frames:     int         = 0
    first_seen: float       = 0.0
    last_seen:  float       = 0.0

    @property
    def active_seconds(self) -> float:
        return round(self.last_seen - self.first_seen, 2)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["active_seconds"] = self.active_seconds
        return d


@dataclass
class AnalysisResult:
    file:     str
    frames:   int
    duration: float
    aps:      list[AccessPoint] = field(default_factory=list)
    clients:  list[Client]      = field(default_factory=list)

    @property
    def channel_stats(self) -> dict[int, int]:
        """Return {channel: beacon_count} for known channels."""
        stats: dict[int, int] = {}
        for ap in self.aps:
            if ap.channel is not None:
                stats[ap.channel] = stats.get(ap.channel, 0) + ap.beacons
        return dict(sorted(stats.items()))

    def to_dict(self) -> dict:
        return {
            "file":          self.file,
            "frames":        self.frames,
            "duration":      self.duration,
            "channel_stats": self.channel_stats,
            "aps":           [ap.to_dict() for ap in self.aps],
            "clients":       [c.to_dict()  for c in self.clients],
        }


# ── helpers ───────────────────────────────────────────────────────────────────

def _norm_mac(addr: str | None) -> str:
    """Normalise MAC address to uppercase colon-separated format."""
    return addr.upper() if addr else UNKNOWN_MAC


def _iter_elts(packet) -> Iterator[Dot11Elt]:
    """Yield all Dot11Elt layers from *packet* without recursive getlayer calls."""
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        yield elt
        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None


def _channel_from_elt(packet) -> int | None:
    """Extract channel from DS Parameter Set (ID=3)."""
    for elt in _iter_elts(packet):
        if elt.ID == DOT11_ELT_DS and len(elt.info) >= 1:
            return int(elt.info[0])
    return None


def _ssid_from_elt(packet) -> str:
    """Decode SSID from first Dot11Elt (ID=0). Returns '<hidden>' for empty/null SSID."""
    for elt in _iter_elts(packet):
        if elt.ID == DOT11_ELT_SSID:
            raw = elt.info
            if not raw:
                return "<hidden>"
            return raw.decode("utf-8", errors="replace").strip("\x00") or "<hidden>"
    return "<hidden>"


def _enc_from_elt(packet) -> str:
    """
    Detect encryption from RSN (ID=48) and vendor (ID=221) elements.
    Returns one of: WPA3, WPA2, WPA, OPEN/WEP.
    """
    has_rsn  = False
    has_wpa  = False
    rsn_data = b""

    for elt in _iter_elts(packet):
        if elt.ID == DOT11_ELT_RSN:
            has_rsn  = True
            rsn_data = elt.info
        elif elt.ID == DOT11_ELT_VENDOR and elt.info[:4] == WPA_OUI:
            has_wpa = True

    if has_rsn:
        # AKM Suite offset: version(2) + group(4) + pairwise_count(2) + pairwise(4*n) + akm_count(2) + akm_list
        # Quick check: OUI 00:0F:AC suite type 8 = SAE → WPA3
        if b"\x00\x0f\xac\x08" in rsn_data:
            return "WPA3"
        return "WPA2"
    if has_wpa:
        return "WPA"
    return "OPEN/WEP"


# ── core parser ───────────────────────────────────────────────────────────────

def parse_pcap(path: str | Path) -> AnalysisResult:
    """
    Parse a PCAP/PCAPNG file and return a structured :class:`AnalysisResult`.

    Parameters
    ----------
    path:
        Path to the capture file.

    Returns
    -------
    AnalysisResult
        Structured summary with APs, clients, frame count and duration.
    """
    path = str(path)
    log.info("Loading %s …", path)

    packets = rdpcap(path)
    frame_count = len(packets)

    aps:     dict[str, AccessPoint] = {}
    clients: dict[str, Client]      = {}
    timestamps: list[float]         = []

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        ts     = float(pkt.time)
        dot11  = pkt.getlayer(Dot11)
        bssid  = _norm_mac(dot11.addr3)

        timestamps.append(ts)

        # ── Beacon / Probe Response → AP metadata ────────────────────────────
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid    = _ssid_from_elt(pkt)
            channel = _channel_from_elt(pkt)
            enc     = _enc_from_elt(pkt)

            if bssid not in aps:
                aps[bssid] = AccessPoint(
                    bssid=bssid, ssid=ssid,
                    channel=channel, enc=enc,
                    first_seen=ts, last_seen=ts,
                )
            ap = aps[bssid]
            ap.beacons  += 1
            ap.last_seen = max(ap.last_seen, ts)
            # Update SSID if we previously saw it as hidden
            if ap.ssid == "<hidden>" and ssid != "<hidden>":
                ap.ssid = ssid

        # ── Management / Data frames → client activity ───────────────────────
        if dot11.type in (0, 2):
            src = _norm_mac(dot11.addr2)
            dst = _norm_mac(dot11.addr1)

            for mac in (src, dst):
                if mac == UNKNOWN_MAC or mac.startswith(BROADCAST_MAC[:8]):
                    continue
                if mac not in clients:
                    clients[mac] = Client(
                        mac=mac, bssid_ref=bssid,
                        first_seen=ts, last_seen=ts,
                    )
                c            = clients[mac]
                c.frames    += 1
                c.last_seen  = max(c.last_seen, ts)

    duration = round(max(timestamps) - min(timestamps), 2) if len(timestamps) > 1 else 0.0

    return AnalysisResult(
        file=path,
        frames=frame_count,
        duration=duration,
        aps=list(aps.values()),
        clients=list(clients.values()),
    )


def parse_directory(directory: str | Path) -> list[AnalysisResult]:
    """
    Parse all PCAP files in *directory* (non-recursive).

    Returns a list of :class:`AnalysisResult` objects, one per file.
    """
    directory = Path(directory)
    files = [f for f in directory.iterdir() if f.suffix.lower() in PCAP_EXTENSIONS]
    if not files:
        log.warning("No PCAP files found in %s", directory)
        return []
    return [parse_pcap(f) for f in sorted(files)]


# ── display ───────────────────────────────────────────────────────────────────

def print_summary(result: AnalysisResult) -> None:
    """Pretty-print the analysis summary to the terminal."""
    if RICH:
        _print_rich(result)
    else:
        _print_plain(result)


def _print_rich(result: AnalysisResult) -> None:
    assert console is not None

    console.print(Panel.fit(
        f"[bold cyan]File:[/]            {result.file}\n"
        f"[bold cyan]Total frames:[/]    {result.frames}\n"
        f"[bold cyan]Capture duration:[/]{result.duration}s\n"
        f"[bold cyan]Access Points:[/]   {len(result.aps)}\n"
        f"[bold cyan]Client MACs:[/]     {len(result.clients)}",
        title="📡 PCAP Analysis Summary",
        border_style="cyan",
    ))

    # ── AP table ─────────────────────────────────────────────────────────────
    ap_table = Table(
        title=f"Access Points ({len(result.aps)})",
        box=box.ROUNDED, border_style="blue", show_lines=False,
    )
    for col, style in (
        ("BSSID", "yellow"), ("SSID", "white"), ("Ch", "cyan"),
        ("Encryption", "green"), ("Beacons", "magenta"), ("Active (s)", "dim"),
    ):
        ap_table.add_column(col, style=style)

    for ap in sorted(result.aps, key=lambda x: (x.channel or 99, x.ssid)):
        enc_color = {"WPA3": "bright_green", "WPA2": "green",
                     "WPA": "yellow", "OPEN/WEP": "red"}.get(ap.enc, "white")
        ap_table.add_row(
            ap.bssid,
            ap.ssid[:32],
            str(ap.channel or "?"),
            f"[{enc_color}]{ap.enc}[/]",
            str(ap.beacons),
            str(ap.active_seconds),
        )
    console.print(ap_table)

    # ── Client table ──────────────────────────────────────────────────────────
    top_clients = sorted(result.clients, key=lambda x: x.frames, reverse=True)[:MAX_CLIENTS_SHOWN]
    cli_table = Table(
        title=f"Active Clients (top {MAX_CLIENTS_SHOWN})",
        box=box.ROUNDED, border_style="magenta",
    )
    for col, style in (
        ("MAC", "yellow"), ("Frames", "cyan"), ("Associated BSSID", "white"), ("Active (s)", "dim"),
    ):
        cli_table.add_column(col, style=style)
    for c in top_clients:
        cli_table.add_row(c.mac, str(c.frames), c.bssid_ref, str(c.active_seconds))
    console.print(cli_table)

    # ── Channel statistics ────────────────────────────────────────────────────
    ch_stats = result.channel_stats
    if ch_stats:
        ch_table = Table(title="Channel Utilisation", box=box.SIMPLE, border_style="dim")
        ch_table.add_column("Channel", style="cyan")
        ch_table.add_column("Beacons", style="white")
        ch_table.add_column("Bar", style="green")
        max_val = max(ch_stats.values())
        for ch, count in ch_stats.items():
            bar = "█" * int(30 * count / max_val)
            ch_table.add_row(str(ch), str(count), bar)
        console.print(ch_table)


def _print_plain(result: AnalysisResult) -> None:
    print(f"\n=== PCAP Analysis: {result.file} ===")
    print(f"Total frames  : {result.frames}")
    print(f"Duration      : {result.duration}s")
    print(f"Access Points : {len(result.aps)}")
    print(f"Client MACs   : {len(result.clients)}\n")

    hdr = f"{'BSSID':<20} {'SSID':<32} {'Ch':>3} {'Enc':<10} {'Beacons':>7} {'Active(s)':>9}"
    print(hdr)
    print("-" * len(hdr))
    for ap in sorted(result.aps, key=lambda x: (x.channel or 99, x.ssid)):
        print(
            f"{ap.bssid:<20} {ap.ssid[:32]:<32} {str(ap.channel or '?'):>3} "
            f"{ap.enc:<10} {ap.beacons:>7} {ap.active_seconds:>9}"
        )

    print("\n--- Channel Stats ---")
    for ch, count in result.channel_stats.items():
        print(f"  Ch {ch:>2}: {count} beacons")


# ── export ────────────────────────────────────────────────────────────────────

def _out_path(result: AnalysisResult, out_dir: str, suffix: str) -> Path:
    stem = Path(result.file).stem
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(out_dir) / f"{stem}_{ts}{suffix}"


def export_csv(result: AnalysisResult, out_dir: str = "reports") -> None:
    """Export AP and client tables as CSV files (requires pandas)."""
    if not HAS_PANDAS:
        log.error("pandas is required for CSV export. Run: pip install pandas")
        return
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    base = Path(result.file).stem
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")

    ap_path  = Path(out_dir) / f"{base}_aps_{ts}.csv"
    cli_path = Path(out_dir) / f"{base}_clients_{ts}.csv"

    pd.DataFrame([ap.to_dict() for ap in result.aps]).to_csv(ap_path, index=False)
    pd.DataFrame([c.to_dict()  for c in result.clients]).to_csv(cli_path, index=False)

    log.info("[export CSV] APs     → %s", ap_path)
    log.info("[export CSV] Clients → %s", cli_path)


def export_json(result: AnalysisResult, out_dir: str = "reports") -> None:
    """Export full analysis result as a JSON file."""
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    out = _out_path(result, out_dir, ".json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
    log.info("[export JSON] → %s", out)


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline 802.11 PCAP analyzer for ESP32 captures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer/pcap_analyzer.py --file captures/sample.pcap
  python analyzer/pcap_analyzer.py --file captures/sample.pcap --export csv json
  python analyzer/pcap_analyzer.py --dir captures/ --export csv
  python analyzer/pcap_analyzer.py --file captures/sample.pcap --plot
        """,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", metavar="FILE", help="Path to a .pcap / .pcapng file")
    source.add_argument("--dir",  metavar="DIR",  help="Directory of PCAP files to batch-process")

    parser.add_argument(
        "--export",
        nargs="+",
        choices=["csv", "json"],
        default=[],
        metavar="FMT",
        help="Export formats (csv, json); multiple allowed",
    )
    parser.add_argument(
        "--out-dir",
        default="reports",
        metavar="DIR",
        help="Output directory for exported files (default: reports/)",
    )
    parser.add_argument("--plot",    action="store_true", help="Generate channel utilisation plot")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


def _process_result(result: AnalysisResult, args: argparse.Namespace) -> None:
    print_summary(result)

    if "csv" in args.export:
        export_csv(result, args.out_dir)
    if "json" in args.export:
        export_json(result, args.out_dir)

    if args.plot:
        try:
            from analyzer.visualizer import plot_channel_utilization  # type: ignore
            plot_channel_utilization(result)
        except ImportError:
            log.warning("matplotlib not available — skipping plot")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    results: list[AnalysisResult] = []

    if args.file:
        p = Path(args.file)
        if not p.is_file():
            log.error("File not found: %s", args.file)
            return 1
        if p.suffix.lower() not in PCAP_EXTENSIONS:
            log.warning("Unexpected file extension: %s", p.suffix)
        results.append(parse_pcap(p))
    else:
        d = Path(args.dir)
        if not d.is_dir():
            log.error("Directory not found: %s", args.dir)
            return 1
        results = parse_directory(d)
        if not results:
            return 1

    for result in results:
        _process_result(result, args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
