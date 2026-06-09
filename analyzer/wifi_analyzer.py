"""
wifi_analyzer.py
----------------
Parses and classifies IEEE 802.11 frames from ESP32 serial monitor logs.

Usage:
    python wifi_analyzer.py --log monitor.log
    python wifi_analyzer.py --log monitor.log --export results.json
"""

import re
import json
import argparse
from collections import defaultdict
from datetime import datetime


# -----------------------------------------------------------------
# IEEE 802.11 Frame Type Definitions
# -----------------------------------------------------------------

FRAME_TYPES = {
    # Management frames
    0x00: "Association Request",
    0x10: "Association Response",
    0x20: "Reassociation Request",
    0x30: "Reassociation Response",
    0x40: "Probe Request",
    0x50: "Probe Response",
    0x80: "Beacon",
    0xA0: "Disassociation",
    0xB0: "Authentication",
    0xC0: "Deauthentication",
    # Control frames
    0x18: "Block Ack Request",
    0x19: "Block Ack",
    0x1A: "PS-Poll",
    0x1B: "RTS",
    0x1C: "CTS",
    0x1D: "ACK",
    # Data frames
    0x08: "Data",
    0x88: "QoS Data",
    0x09: "Data + CF-Ack",
}

FRAME_CATEGORIES = {
    "management": [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x80, 0xA0, 0xB0, 0xC0],
    "control":    [0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D],
    "data":       [0x08, 0x88, 0x09],
}


def classify_frame(frame_type_byte: int) -> tuple[str, str]:
    """Return (type_name, category) for a given frame type byte."""
    name = FRAME_TYPES.get(frame_type_byte, f"Unknown (0x{frame_type_byte:02X})")
    for category, types in FRAME_CATEGORIES.items():
        if frame_type_byte in types:
            return name, category
    return name, "unknown"


# -----------------------------------------------------------------
# Log Parser
# -----------------------------------------------------------------

# Matches lines like:
#   [FRAME] type=0x80 src=AA:BB:CC:DD:EE:FF dst=FF:FF:FF:FF:FF:FF rssi=-65 ch=6
LOG_PATTERN = re.compile(
    r"\[FRAME\]\s+"
    r"type=0x(?P<type>[0-9A-Fa-f]{2})\s+"
    r"src=(?P<src>[0-9A-Fa-f:]{17})\s+"
    r"dst=(?P<dst>[0-9A-Fa-f:]{17})\s+"
    r"rssi=(?P<rssi>-?\d+)\s+"
    r"ch=(?P<channel>\d+)"
)

# Optional SSID on beacon lines:
#   [BEACON] ssid=MyNetwork bssid=AA:BB:CC:DD:EE:FF ch=6 rssi=-72
BEACON_PATTERN = re.compile(
    r"\[BEACON\]\s+"
    r"ssid=(?P<ssid>\S+)\s+"
    r"bssid=(?P<bssid>[0-9A-Fa-f:]{17})\s+"
    r"ch=(?P<channel>\d+)\s+"
    r"rssi=(?P<rssi>-?\d+)"
)


def parse_log(filepath: str) -> dict:
    """
    Parse an ESP32 serial monitor log file.

    Returns a dict with:
      - frames: list of parsed frame dicts
      - networks: dict of discovered SSIDs -> metadata
      - stats: summary statistics
    """
    frames = []
    networks = {}
    channel_counter = defaultdict(int)
    mac_counter = defaultdict(int)
    category_counter = defaultdict(int)
    rssi_values = []
    unknown_lines = 0

    with open(filepath, "r", errors="replace") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            # Try frame match
            frame_match = LOG_PATTERN.search(line)
            if frame_match:
                ftype = int(frame_match.group("type"), 16)
                rssi  = int(frame_match.group("rssi"))
                ch    = int(frame_match.group("channel"))
                src   = frame_match.group("src").upper()
                dst   = frame_match.group("dst").upper()

                name, category = classify_frame(ftype)
                frames.append({
                    "line":      line_number,
                    "type_byte": ftype,
                    "type_name": name,
                    "category":  category,
                    "src":       src,
                    "dst":       dst,
                    "rssi":      rssi,
                    "channel":   ch,
                })

                channel_counter[ch] += 1
                mac_counter[src]    += 1
                category_counter[category] += 1
                rssi_values.append(rssi)
                continue

            # Try beacon match
            beacon_match = BEACON_PATTERN.search(line)
            if beacon_match:
                ssid  = beacon_match.group("ssid")
                bssid = beacon_match.group("bssid").upper()
                ch    = int(beacon_match.group("channel"))
                rssi  = int(beacon_match.group("rssi"))

                if ssid not in networks:
                    networks[ssid] = {
                        "bssid":    bssid,
                        "channel":  ch,
                        "rssi_min": rssi,
                        "rssi_max": rssi,
                        "beacons":  1,
                    }
                else:
                    net = networks[ssid]
                    net["rssi_min"] = min(net["rssi_min"], rssi)
                    net["rssi_max"] = max(net["rssi_max"], rssi)
                    net["beacons"] += 1
                continue

            # Lines with content we didn't parse
            if line and not line.startswith("#"):
                unknown_lines += 1

    # Build summary stats
    avg_rssi = round(sum(rssi_values) / len(rssi_values), 2) if rssi_values else None
    stats = {
        "total_frames":     len(frames),
        "total_networks":   len(networks),
        "frames_by_category": dict(category_counter),
        "frames_by_channel":  dict(channel_counter),
        "top_talkers":        sorted(mac_counter.items(), key=lambda x: -x[1])[:10],
        "avg_rssi":           avg_rssi,
        "min_rssi":           min(rssi_values) if rssi_values else None,
        "max_rssi":           max(rssi_values) if rssi_values else None,
        "unknown_lines":      unknown_lines,
        "parsed_at":          datetime.utcnow().isoformat() + "Z",
    }

    return {"frames": frames, "networks": networks, "stats": stats}


# -----------------------------------------------------------------
# CLI
# -----------------------------------------------------------------

def print_summary(result: dict) -> None:
    stats    = result["stats"]
    networks = result["networks"]

    print("\n" + "=" * 55)
    print("  IEEE 802.11 Frame Analysis — Summary")
    print("=" * 55)
    print(f"  Total frames parsed : {stats['total_frames']}")
    print(f"  Unique networks     : {stats['total_networks']}")
    print(f"  Avg RSSI            : {stats['avg_rssi']} dBm")
    print(f"  RSSI range          : {stats['min_rssi']} / {stats['max_rssi']} dBm")

    print("\n  Frames by category:")
    for cat, count in stats["frames_by_category"].items():
        print(f"    {cat:<12} {count}")

    print("\n  Frames by channel:")
    for ch, count in sorted(stats["frames_by_channel"].items()):
        bar = "█" * min(count, 40)
        print(f"    CH {ch:>2}  {bar} {count}")

    print("\n  Top talkers (by frame count):")
    for mac, count in stats["top_talkers"]:
        print(f"    {mac}   {count} frames")

    if networks:
        print("\n  Discovered networks:")
        for ssid, meta in networks.items():
            print(f"    {ssid:<30} CH {meta['channel']}  RSSI [{meta['rssi_min']}, {meta['rssi_max']}] dBm")

    print("=" * 55 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze IEEE 802.11 frames from an ESP32 serial log."
    )
    parser.add_argument("--log",    required=True, help="Path to the ESP32 monitor log file")
    parser.add_argument("--export", default=None,  help="Export parsed results to a JSON file")
    args = parser.parse_args()

    print(f"[*] Parsing log: {args.log}")
    result = parse_log(args.log)
    print_summary(result)

    if args.export:
        with open(args.export, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Results exported to {args.export}")


if __name__ == "__main__":
    main()
