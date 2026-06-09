"""
pcap_parser.py
--------------
Reads .pcap AND .pcapng files captured by the ESP32 and extracts
rich IEEE 802.11 frame metadata without relying on Scapy or Wireshark.

Parsed per frame:
  - Frame type / subtype (human readable)
  - Source MAC, Destination MAC, BSSID
  - RSSI (dBm)  ← from radiotap header
  - Channel     ← from radiotap header
  - Data rate   ← from radiotap header
  - SSID        ← from beacon / probe-response body
  - Beacon interval & capabilities ← from beacon body
  - Timestamp, frame size

The --export JSON is structured so report_generator.py can build
RSSI charts, channel charts, and the networks table directly.

Usage:
    python pcap_parser.py --file capture.pcap
    python pcap_parser.py --file capture.pcapng
    python pcap_parser.py --file capture.pcapng --export frames.json
    python pcap_parser.py --file capture.pcapng --filter "Beacon" --limit 500
"""

import struct
import json
import argparse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Generator, Optional


# ─────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────

LINKTYPE_IEEE802_11          = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127

PCAP_MAGIC_LE    = 0xA1B2C3D4
PCAP_MAGIC_BE    = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D

BT_SHB = 0x0A0D0D0A
BT_IDB = 0x00000001
BT_EPB = 0x00000006
BT_SPB = 0x00000003
BT_OPB = 0x00000002

SHB_BYTE_ORDER_MAGIC = 0x1A2B3C4D

# Radiotap field presence bitmask positions
RT_TSFT        = 0
RT_FLAGS       = 1
RT_RATE        = 2
RT_CHANNEL     = 3
RT_FHSS        = 4
RT_DBM_SIGNAL  = 5   # RSSI in dBm (signed byte)
RT_DBM_NOISE   = 6
RT_LOCK_QUAL   = 7
RT_TX_ATTEN    = 8
RT_DB_TX_ATTEN = 9
RT_DBM_TX_POW  = 10
RT_ANTENNA     = 11
RT_DB_SIGNAL   = 12

# Radiotap field sizes (bytes) in order of bit position
RT_FIELD_SIZES = {
    RT_TSFT:        (8, 8),   # (size, alignment)
    RT_FLAGS:       (1, 1),
    RT_RATE:        (1, 1),
    RT_CHANNEL:     (4, 2),   # freq(2) + flags(2)
    RT_FHSS:        (2, 2),
    RT_DBM_SIGNAL:  (1, 1),
    RT_DBM_NOISE:   (1, 1),
    RT_LOCK_QUAL:   (2, 2),
    RT_TX_ATTEN:    (2, 2),
    RT_DB_TX_ATTEN: (2, 2),
    RT_DBM_TX_POW:  (1, 1),
    RT_ANTENNA:     (1, 1),
    RT_DB_SIGNAL:   (1, 1),
}

# 802.11 frequency → channel mapping
FREQ_TO_CHANNEL = {
    2412: 1,  2417: 2,  2422: 3,  2427: 4,  2432: 5,
    2437: 6,  2442: 7,  2447: 8,  2452: 9,  2457: 10,
    2462: 11, 2467: 12, 2472: 13, 2484: 14,
    5180: 36, 5200: 40, 5220: 44, 5240: 48,
    5260: 52, 5280: 56, 5300: 60, 5320: 64,
    5500: 100,5520: 104,5540: 108,5560: 112,5580: 116,
    5600: 120,5620: 124,5640: 128,5660: 132,5680: 136,
    5700: 140,5720: 144,5745: 149,5765: 153,5785: 157,
    5805: 161,5825: 165,
}

# 802.11 capability flags (byte 0 of capability info)
CAP_ESS     = 0x0001
CAP_IBSS    = 0x0002
CAP_PRIVACY = 0x0010   # WEP bit — if set, some encryption is present


# ─────────────────────────────────────────────────────────────────
# Data class
# ─────────────────────────────────────────────────────────────────

@dataclass
class Frame:
    # Identification
    index:      int
    source_fmt: str           # "pcap" | "pcapng"

    # Timing
    ts_sec:     int
    ts_usec:    int

    # Size
    orig_len:   int
    incl_len:   int

    # 802.11 frame metadata
    frame_type: str
    frame_ctrl: int
    src_mac:    str
    dst_mac:    str
    bssid:      str

    # Radiotap enrichment (None if not available)
    rssi:       Optional[int]   = None   # dBm
    channel:    Optional[int]   = None
    frequency:  Optional[int]   = None   # MHz
    data_rate:  Optional[float] = None   # Mbps
    radiotap:   bool            = False

    # Beacon / Probe-Response enrichment
    ssid:             Optional[str] = None
    beacon_interval:  Optional[int] = None   # ms
    encryption:       Optional[str] = None   # "Open" | "WEP" | "WPA/WPA2"
    network_type:     Optional[str] = None   # "Infrastructure" | "Ad-Hoc"


# ─────────────────────────────────────────────────────────────────
# Radiotap parser
# ─────────────────────────────────────────────────────────────────

def _parse_radiotap(data: bytes) -> dict:
    """
    Parse the radiotap header and return a dict with:
      rssi, channel, frequency, data_rate
    Returns an empty dict on any parse error.
    """
    result = {}
    try:
        if len(data) < 8:
            return result

        # Header: version(1) pad(1) len(2) present_flags(4)
        rt_len    = struct.unpack_from("<H", data, 2)[0]
        present   = struct.unpack_from("<I", data, 4)[0]

        # Offset starts after the fixed 8-byte header.
        # If bit 31 (EXT) is set there are more present-flag words — skip them.
        offset = 8
        while present & (1 << 31):
            if offset + 4 > rt_len:
                break
            present = struct.unpack_from("<I", data, offset)[0]
            offset += 4

        # Walk through fields in bit order
        for bit in range(13):
            if not (present & (1 << bit)):
                continue
            if bit not in RT_FIELD_SIZES:
                break

            size, align = RT_FIELD_SIZES[bit]

            # Align offset
            if align > 1:
                offset = (offset + align - 1) & ~(align - 1)

            if offset + size > rt_len or offset + size > len(data):
                break

            if bit == RT_RATE:
                rate_raw = data[offset]
                result["data_rate"] = rate_raw * 0.5   # units are 500 Kbps

            elif bit == RT_CHANNEL:
                freq  = struct.unpack_from("<H", data, offset)[0]
                result["frequency"] = freq
                result["channel"]   = FREQ_TO_CHANNEL.get(freq)

            elif bit == RT_DBM_SIGNAL:
                # Signed byte
                rssi_raw = struct.unpack_from("b", data, offset)[0]
                result["rssi"] = rssi_raw

            offset += size

    except Exception:
        pass

    return result


# ─────────────────────────────────────────────────────────────────
# 802.11 frame parsers
# ─────────────────────────────────────────────────────────────────

def _mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def _parse_frame_control(fc: int) -> str:
    ftype   = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    mgmt = {
        0: "Association Request",   1: "Association Response",
        2: "Reassociation Request", 3: "Reassociation Response",
        4: "Probe Request",         5: "Probe Response",
        8: "Beacon",               10: "Disassociation",
       11: "Authentication",       12: "Deauthentication",
    }
    ctrl = {8: "Block Ack Request", 9: "Block Ack",
           10: "PS-Poll", 11: "RTS", 12: "CTS", 13: "ACK"}
    data = {0: "Data", 1: "Data+CF-Ack", 2: "Data+CF-Poll", 8: "QoS Data"}

    if ftype == 0:   return mgmt.get(subtype, f"Management/{subtype}")
    elif ftype == 1: return ctrl.get(subtype, f"Control/{subtype}")
    elif ftype == 2: return data.get(subtype, f"Data/{subtype}")
    else:            return f"Reserved/{subtype}"


def _parse_beacon_body(data: bytes, dot11_offset: int) -> dict:
    """
    Parse the body of a Beacon or Probe Response frame.
    dot11_offset points to the start of the 802.11 header within `data`.
    Returns dict with: ssid, beacon_interval, encryption, network_type
    """
    result = {}
    try:
        # 802.11 fixed header = FC(2)+Dur(2)+Addr1(6)+Addr2(6)+Addr3(6)+SeqCtrl(2) = 24
        # Beacon fixed params = Timestamp(8)+Beacon Interval(2)+Capability Info(2) = 12
        body_offset = dot11_offset + 24 + 12

        if body_offset > len(data):
            return result

        # Beacon interval and capability info are just before tagged params
        bi_offset  = dot11_offset + 24 + 8
        cap_offset = dot11_offset + 24 + 10

        if cap_offset + 2 <= len(data):
            beacon_interval = struct.unpack_from("<H", data, bi_offset)[0]
            cap_info        = struct.unpack_from("<H", data, cap_offset)[0]
            result["beacon_interval"] = beacon_interval

            # Network type
            if cap_info & CAP_ESS:
                result["network_type"] = "Infrastructure"
            elif cap_info & CAP_IBSS:
                result["network_type"] = "Ad-Hoc"

            # Encryption (basic — WEP bit only; WPA needs IE parsing below)
            result["encryption"] = "WEP" if (cap_info & CAP_PRIVACY) else "Open"

        # Walk tagged parameters (Information Elements)
        offset = body_offset
        while offset + 2 <= len(data):
            tag_num = data[offset]
            tag_len = data[offset + 1]
            offset += 2

            if offset + tag_len > len(data):
                break

            tag_data = data[offset : offset + tag_len]

            # Tag 0: SSID
            if tag_num == 0:
                try:
                    ssid = tag_data.decode("utf-8", errors="replace").strip("\x00")
                    result["ssid"] = ssid if ssid else "<hidden>"
                except Exception:
                    result["ssid"] = "<decode error>"

            # Tag 48: RSN (WPA2) / Tag 221 with OUI 00:50:F2:01: WPA1
            elif tag_num == 48:
                result["encryption"] = "WPA2"
            elif tag_num == 221 and tag_len >= 4:
                oui_type = tag_data[:4]
                if oui_type == bytes([0x00, 0x50, 0xF2, 0x01]):
                    if result.get("encryption") not in ("WPA2",):
                        result["encryption"] = "WPA"

            offset += tag_len

    except Exception:
        pass

    return result


def _parse_full_frame(raw: bytes, has_radiotap: bool) -> dict:
    """
    Parse a raw 802.11 frame (with optional radiotap prefix).
    Returns a dict with all extracted fields.
    """
    UNKNOWN = "??:??:??:??:??:??"
    out = {
        "frame_ctrl": 0, "frame_type": "Unknown",
        "src_mac": UNKNOWN, "dst_mac": UNKNOWN, "bssid": UNKNOWN,
        "rssi": None, "channel": None, "frequency": None,
        "data_rate": None, "radiotap": has_radiotap,
        "ssid": None, "beacon_interval": None,
        "encryption": None, "network_type": None,
    }

    rt_info    = {}
    dot11_off  = 0

    if has_radiotap:
        if len(raw) < 4:
            return out
        rt_len    = struct.unpack_from("<H", raw, 2)[0]
        rt_info   = _parse_radiotap(raw)
        dot11_off = rt_len

    out.update({k: v for k, v in rt_info.items() if v is not None})

    if dot11_off + 24 > len(raw):
        return out

    fc    = struct.unpack_from("<H", raw, dot11_off)[0]
    out["frame_ctrl"] = fc
    out["frame_type"] = _parse_frame_control(fc)
    out["dst_mac"]  = _mac_to_str(raw[dot11_off + 4  : dot11_off + 10])
    out["src_mac"]  = _mac_to_str(raw[dot11_off + 10 : dot11_off + 16])
    out["bssid"]    = _mac_to_str(raw[dot11_off + 16 : dot11_off + 22])

    # Deep-parse Beacon and Probe Response frames
    ftype   = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if ftype == 0 and subtype in (5, 8):   # Probe Response or Beacon
        beacon_info = _parse_beacon_body(raw, dot11_off)
        out.update({k: v for k, v in beacon_info.items() if v is not None})

    return out


# ─────────────────────────────────────────────────────────────────
# Format detection
# ─────────────────────────────────────────────────────────────────

def _detect_format(filepath: str) -> str:
    with open(filepath, "rb") as f:
        magic_bytes = f.read(4)
    if len(magic_bytes) < 4:
        raise ValueError("File is too small to identify.")
    magic = struct.unpack("<I", magic_bytes)[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_BE):
        return "pcap"
    if magic == BT_SHB:
        return "pcapng"
    raise ValueError(
        f"Unrecognised format (magic: 0x{magic:08X}). Expected .pcap or .pcapng."
    )


# ─────────────────────────────────────────────────────────────────
# Classic PCAP reader
# ─────────────────────────────────────────────────────────────────

def _iter_pcap(filepath: str, limit: int) -> Generator[Frame, None, None]:
    with open(filepath, "rb") as f:
        raw_hdr = f.read(24)
        magic   = struct.unpack("<I", raw_hdr[:4])[0]
        endian  = "<" if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE) else ">"
        network = struct.unpack(endian + "IHHiIII", raw_hdr)[6]
        has_radiotap = (network == LINKTYPE_IEEE802_11_RADIOTAP)
        index = 0

        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
            raw_frame = f.read(incl_len)
            if len(raw_frame) < incl_len:
                break

            info = _parse_full_frame(raw_frame, has_radiotap)

            yield Frame(
                index=           index,
                source_fmt=      "pcap",
                ts_sec=          ts_sec,
                ts_usec=         ts_usec,
                orig_len=        orig_len,
                incl_len=        incl_len,
                frame_type=      info["frame_type"],
                frame_ctrl=      info["frame_ctrl"],
                src_mac=         info["src_mac"],
                dst_mac=         info["dst_mac"],
                bssid=           info["bssid"],
                rssi=            info["rssi"],
                channel=         info["channel"],
                frequency=       info["frequency"],
                data_rate=       info["data_rate"],
                radiotap=        info["radiotap"],
                ssid=            info["ssid"],
                beacon_interval= info["beacon_interval"],
                encryption=      info["encryption"],
                network_type=    info["network_type"],
            )
            index += 1
            if limit and index >= limit:
                break


# ─────────────────────────────────────────────────────────────────
# PCAPNG reader
# ─────────────────────────────────────────────────────────────────

def _read_pcapng_block(f, endian: str):
    hdr = f.read(8)
    if len(hdr) < 8:
        return None
    block_type, total_len = struct.unpack(endian + "II", hdr)
    if total_len < 12 or total_len % 4 != 0:
        return None
    body = f.read(total_len - 12)
    f.read(4)   # trailing length copy
    return block_type, body


def _iter_pcapng(filepath: str, limit: int) -> Generator[Frame, None, None]:
    with open(filepath, "rb") as f:
        f.read(4)                                        # block type (SHB)
        shb_total = struct.unpack("<I", f.read(4))[0]   # total length
        bom       = struct.unpack("<I", f.read(4))[0]   # byte order magic

        endian = "<" if bom == SHB_BYTE_ORDER_MAGIC else ">"
        f.read(shb_total - 12)                           # skip rest of SHB

        interfaces: list[int] = []
        index = 0

        while True:
            block = _read_pcapng_block(f, endian)
            if block is None:
                break
            block_type, body = block

            if block_type == BT_IDB:
                lt = struct.unpack(endian + "H", body[:2])[0] if len(body) >= 2 else 0
                interfaces.append(lt)
                continue

            raw_frame = None
            ts_sec = ts_usec = orig_len = cap_len = 0
            iface_id = 0

            if block_type == BT_EPB and len(body) >= 20:
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    endian + "IIIII", body[:20]
                )
                ts_combined = (ts_high << 32) | ts_low
                ts_sec  = ts_combined // 1_000_000
                ts_usec = ts_combined  % 1_000_000
                raw_frame = body[20 : 20 + cap_len]

            elif block_type == BT_SPB and len(body) >= 4:
                orig_len  = struct.unpack(endian + "I", body[:4])[0]
                raw_frame = body[4:]
                cap_len   = len(raw_frame)

            elif block_type == BT_OPB and len(body) >= 18:
                iface_id, _, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    endian + "HHHIII", body[:18]
                )
                ts_combined = (ts_high << 32) | ts_low
                ts_sec  = ts_combined // 1_000_000
                ts_usec = ts_combined  % 1_000_000
                raw_frame = body[18 : 18 + cap_len]

            if raw_frame is None:
                continue

            linktype     = interfaces[iface_id] if iface_id < len(interfaces) else 0
            has_radiotap = (linktype == LINKTYPE_IEEE802_11_RADIOTAP)
            info         = _parse_full_frame(raw_frame, has_radiotap)

            yield Frame(
                index=           index,
                source_fmt=      "pcapng",
                ts_sec=          ts_sec,
                ts_usec=         ts_usec,
                orig_len=        orig_len,
                incl_len=        cap_len,
                frame_type=      info["frame_type"],
                frame_ctrl=      info["frame_ctrl"],
                src_mac=         info["src_mac"],
                dst_mac=         info["dst_mac"],
                bssid=           info["bssid"],
                rssi=            info["rssi"],
                channel=         info["channel"],
                frequency=       info["frequency"],
                data_rate=       info["data_rate"],
                radiotap=        info["radiotap"],
                ssid=            info["ssid"],
                beacon_interval= info["beacon_interval"],
                encryption=      info["encryption"],
                network_type=    info["network_type"],
            )
            index += 1
            if limit and index >= limit:
                break


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

def iter_frames(filepath: str, limit: int = 0) -> Generator[Frame, None, None]:
    """Yield Frame objects from a .pcap or .pcapng file. Format is auto-detected."""
    fmt = _detect_format(filepath)
    yield from (_iter_pcap if fmt == "pcap" else _iter_pcapng)(filepath, limit)


def build_summary(frames: list[Frame]) -> dict:
    """
    Build a summary dict from a list of Frame objects.
    Compatible with report_generator.py (pcap mode).
    """
    rssi_values  = [f.rssi for f in frames if f.rssi is not None]
    chan_counter  = defaultdict(int)
    type_counter  = defaultdict(int)
    mac_counter   = defaultdict(int)
    cat_counter   = defaultdict(int)

    # Networks: bssid → {ssid, channel, rssi_list, encryption, network_type, frames}
    networks: dict[str, dict] = {}

    for fr in frames:
        type_counter[fr.frame_type] += 1

        ftype = (fr.frame_ctrl >> 2) & 0x3
        cat   = {0: "management", 1: "control", 2: "data"}.get(ftype, "unknown")
        cat_counter[cat] += 1

        if fr.channel:
            chan_counter[fr.channel] += 1

        if fr.src_mac and "?" not in fr.src_mac:
            mac_counter[fr.src_mac] += 1

        bssid = fr.bssid
        if bssid and "?" not in bssid:
            if bssid not in networks:
                networks[bssid] = {
                    "ssid":         fr.ssid or "—",
                    "bssid":        bssid,
                    "channel":      fr.channel or "—",
                    "rssi_list":    [],
                    "encryption":   fr.encryption or "—",
                    "network_type": fr.network_type or "—",
                    "frames":       0,
                    "beacon_interval": fr.beacon_interval,
                }
            net = networks[bssid]
            net["frames"] += 1
            if fr.rssi is not None:
                net["rssi_list"].append(fr.rssi)
            # Update SSID if we find a better one (non-hidden)
            if fr.ssid and fr.ssid not in ("—", "<hidden>", None):
                net["ssid"] = fr.ssid
            if fr.channel:
                net["channel"] = fr.channel
            if fr.encryption and fr.encryption != "Open":
                net["encryption"] = fr.encryption

    # Finalise network rows
    net_rows = []
    for bssid, net in networks.items():
        rlist = net.pop("rssi_list", [])
        net["rssi_min"] = min(rlist) if rlist else "—"
        net["rssi_max"] = max(rlist) if rlist else "—"
        net["rssi_avg"] = round(sum(rlist) / len(rlist), 1) if rlist else "—"
        net["beacons"]  = net.pop("frames")
        net_rows.append(net)
    net_rows.sort(key=lambda x: x["beacons"], reverse=True)

    # RSSI histogram (5 dBm buckets)
    rssi_hist: dict[int, int] = defaultdict(int)
    for v in rssi_values:
        rssi_hist[(v // 5) * 5] += 1

    # Data-rate distribution
    rate_counter: dict[str, int] = defaultdict(int)
    for fr in frames:
        if fr.data_rate is not None:
            rate_counter[f"{fr.data_rate} Mbps"] += 1

    capture_start = min((f.ts_sec for f in frames if f.ts_sec), default=0)
    capture_end   = max((f.ts_sec for f in frames if f.ts_sec), default=0)
    duration_sec  = capture_end - capture_start

    return {
        "total_frames":    len(frames),
        "total_networks":  len(networks),
        "avg_rssi":        round(sum(rssi_values) / len(rssi_values), 2) if rssi_values else None,
        "min_rssi":        min(rssi_values) if rssi_values else None,
        "max_rssi":        max(rssi_values) if rssi_values else None,
        "parsed_at":       datetime.now(timezone.utc).isoformat(),
        "capture_duration_sec": duration_sec,
        "frames_by_category":  dict(cat_counter),
        "frames_by_channel":   {str(k): v for k, v in sorted(chan_counter.items())},
        "frames_by_type":      dict(sorted(type_counter.items(), key=lambda x: -x[1])[:15]),
        "top_talkers":         sorted(mac_counter.items(), key=lambda x: -x[1])[:10],
        "rssi_histogram":      dict(sorted(rssi_hist.items())),
        "data_rates":          dict(sorted(rate_counter.items(),
                                           key=lambda x: float(x[0].split()[0]))),
        "networks":            net_rows,
    }


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────

def _print_summary(summary: dict) -> None:
    s = summary
    dur = s.get("capture_duration_sec", 0)
    dur_str = f"{dur // 60}m {dur % 60}s" if dur else "—"

    print("\n" + "═" * 60)
    print("  IEEE 802.11 Capture Analysis")
    print("═" * 60)
    print(f"  Total frames       : {s['total_frames']:,}")
    print(f"  Unique networks    : {s['total_networks']}")
    print(f"  Capture duration   : {dur_str}")

    if s["avg_rssi"] is not None:
        print(f"  Avg RSSI           : {s['avg_rssi']} dBm")
        print(f"  RSSI range         : {s['min_rssi']} → {s['max_rssi']} dBm")

    if s["frames_by_category"]:
        print("\n  Frame categories:")
        for cat, n in s["frames_by_category"].items():
            pct = n / s["total_frames"] * 100
            print(f"    {cat:<12} {n:>6,}  ({pct:.1f}%)")

    if s["frames_by_channel"]:
        print("\n  Frames per channel:")
        for ch, n in s["frames_by_channel"].items():
            bar = "█" * min(int(n / max(s["frames_by_channel"].values()) * 30), 30)
            print(f"    CH {int(ch):>3}  {bar:<30}  {n:,}")

    if s["networks"]:
        print(f"\n  Discovered networks ({len(s['networks'])}):")
        print(f"    {'SSID':<28} {'BSSID':<20} {'CH':>4}  {'ENC':<8}  {'AVG RSSI':>9}  {'Frames':>7}")
        print("    " + "─" * 84)
        for n in s["networks"]:
            print(
                f"    {str(n['ssid']):<28} {n['bssid']:<20} "
                f"{str(n['channel']):>4}  {str(n['encryption']):<8}  "
                f"{str(n['rssi_avg']):>9}  {n['beacons']:>7,}"
            )

    print("═" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Parse .pcap / .pcapng files from the ESP32. Auto-detects format."
    )
    parser.add_argument("--file",    required=True)
    parser.add_argument("--limit",   type=int, default=0, help="Max frames (0=all)")
    parser.add_argument("--export",  default=None, help="Export enriched frames + summary to JSON")
    parser.add_argument("--filter",  default=None, help="Filter by frame type substring")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print summary and skip frame-by-frame table")
    args = parser.parse_args()

    fmt = _detect_format(args.file)
    print(f"\n[*] File   : {args.file}")
    print(f"[*] Format : {fmt.upper()}")
    print(f"[*] Parsing...", end=" ", flush=True)

    all_frames = list(iter_frames(args.file, limit=args.limit))
    print(f"{len(all_frames):,} frames loaded.")

    summary = build_summary(all_frames)

    filtered = all_frames
    if args.filter:
        filtered = [f for f in all_frames if args.filter.lower() in f.frame_type.lower()]
        print(f"[*] Filter '{args.filter}' → {len(filtered)} frames")

    _print_summary(summary)

    if not args.summary_only:
        print(f"  {'#':<6} {'Timestamp':<12} {'Type':<25} {'SSID':<20} "
              f"{'Src MAC':<20} {'CH':>4} {'RSSI':>6} {'Rate':>8}")
        print("  " + "─" * 105)
        for fr in filtered[:200]:
            ts_str   = f"{fr.ts_sec % 86400 // 3600:02d}:{fr.ts_sec % 3600 // 60:02d}:{fr.ts_sec % 60:02d}"
            ssid_str = (fr.ssid or "")[:19]
            rate_str = f"{fr.data_rate}M" if fr.data_rate else "—"
            rssi_str = f"{fr.rssi}" if fr.rssi is not None else "—"
            ch_str   = str(fr.channel) if fr.channel else "—"
            print(
                f"  {fr.index:<6} {ts_str:<12} {fr.frame_type:<25} {ssid_str:<20} "
                f"{fr.src_mac:<20} {ch_str:>4} {rssi_str:>6} {rate_str:>8}"
            )
        if len(filtered) > 200:
            print(f"\n  ... {len(filtered) - 200} more frames not shown (use --export)")

    if args.export:
        export_data = {
            "summary": summary,
            "frames":  [asdict(f) for f in all_frames],
        }
        with open(args.export, "w") as out:
            json.dump(export_data, out, indent=2)
        print(f"\n[+] Exported → {args.export}")
        print(f"    Contains: summary block + {len(all_frames):,} enriched frames")
        print(f"    Pass to report_generator.py with --mode pcapng")


if __name__ == "__main__":
    main()
