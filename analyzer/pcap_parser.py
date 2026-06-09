"""
pcap_parser.py
--------------
Reads .pcap AND .pcapng files captured by the ESP32 and extracts
IEEE 802.11 frame metadata without relying on Scapy or Wireshark.

Format detection is automatic — just pass the file and the parser
figures out whether it is classic PCAP or PCAPNG.

Supported PCAPNG block types:
  - SHB  (Section Header Block)        — marks the start of a section
  - IDB  (Interface Description Block) — interface / link-type info
  - EPB  (Enhanced Packet Block)        — packet data (most common)
  - SPB  (Simple Packet Block)          — compact packet data
  - OPB  (Obsolete Packet Block)        — legacy, still seen in the wild

Usage:
    python pcap_parser.py --file capture.pcap
    python pcap_parser.py --file capture.pcapng
    python pcap_parser.py --file capture.pcapng --limit 100 --export frames.json
    python pcap_parser.py --file capture.pcapng --filter "Beacon"
"""

import struct
import json
import argparse
from dataclasses import dataclass, asdict
from typing import Generator


# -----------------------------------------------------------------
# Shared constants
# -----------------------------------------------------------------

LINKTYPE_IEEE802_11          = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127

# Classic PCAP magic numbers
PCAP_MAGIC_LE    = 0xA1B2C3D4
PCAP_MAGIC_BE    = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D   # nanosecond variant

# PCAPNG block type codes
BT_SHB = 0x0A0D0D0A
BT_IDB = 0x00000001
BT_EPB = 0x00000006
BT_SPB = 0x00000003
BT_OPB = 0x00000002   # Obsolete Packet Block

# PCAPNG Section Header magic
SHB_BYTE_ORDER_MAGIC = 0x1A2B3C4D


# -----------------------------------------------------------------
# Data class
# -----------------------------------------------------------------

@dataclass
class Frame:
    index:      int
    ts_sec:     int
    ts_usec:    int       # microseconds (or nanoseconds when applicable)
    orig_len:   int
    incl_len:   int
    frame_type: str
    frame_ctrl: int
    src_mac:    str
    dst_mac:    str
    bssid:      str
    radiotap:   bool
    source_fmt: str       # "pcap" or "pcapng"


# -----------------------------------------------------------------
# Shared 802.11 helpers
# -----------------------------------------------------------------

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
    ctrl = {
        8: "Block Ack Request", 9: "Block Ack",
       10: "PS-Poll", 11: "RTS", 12: "CTS", 13: "ACK",
    }
    data = {
        0: "Data", 1: "Data+CF-Ack", 2: "Data+CF-Poll", 8: "QoS Data",
    }

    if ftype == 0:   return mgmt.get(subtype, f"Management/{subtype}")
    elif ftype == 1: return ctrl.get(subtype, f"Control/{subtype}")
    elif ftype == 2: return data.get(subtype, f"Data/{subtype}")
    else:            return f"Reserved/{subtype}"


def _parse_80211(data: bytes, has_radiotap: bool) -> tuple[int, str, str, str]:
    """Return (frame_ctrl, src, dst, bssid) from raw 802.11 bytes."""
    UNKNOWN = "??:??:??:??:??:??"
    offset  = 0

    if has_radiotap:
        if len(data) < 4:
            return 0, UNKNOWN, UNKNOWN, UNKNOWN
        rt_len  = struct.unpack_from("<H", data, 2)[0]
        offset += rt_len

    if offset + 24 > len(data):
        return 0, UNKNOWN, UNKNOWN, UNKNOWN

    fc    = struct.unpack_from("<H", data, offset)[0]
    dst   = _mac_to_str(data[offset + 4  : offset + 10])
    src   = _mac_to_str(data[offset + 10 : offset + 16])
    bssid = _mac_to_str(data[offset + 16 : offset + 22])
    return fc, src, dst, bssid


# -----------------------------------------------------------------
# Format detection
# -----------------------------------------------------------------

def _detect_format(filepath: str) -> str:
    """Return 'pcap' or 'pcapng' by inspecting the first 4 bytes."""
    with open(filepath, "rb") as f:
        magic_bytes = f.read(4)
    if len(magic_bytes) < 4:
        raise ValueError("File is too small to identify.")

    magic = struct.unpack("<I", magic_bytes)[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        return "pcap"
    if magic == PCAP_MAGIC_BE:
        return "pcap"
    if magic == BT_SHB:
        return "pcapng"

    raise ValueError(
        f"Unrecognised file format (first 4 bytes: 0x{magic:08X}). "
        "Expected a .pcap or .pcapng file."
    )


# -----------------------------------------------------------------
# Classic PCAP reader
# -----------------------------------------------------------------

def _iter_pcap(filepath: str, limit: int) -> Generator[Frame, None, None]:
    GLOBAL_HDR = 24
    REC_HDR    = 16

    with open(filepath, "rb") as f:
        raw_hdr = f.read(GLOBAL_HDR)
        magic   = struct.unpack("<I", raw_hdr[:4])[0]

        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian = "<"
        else:
            endian = ">"

        network = struct.unpack(endian + "IHHiIII", raw_hdr)[6]
        has_radiotap = (network == LINKTYPE_IEEE802_11_RADIOTAP)
        index = 0

        while True:
            rec = f.read(REC_HDR)
            if len(rec) < REC_HDR:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
            raw_frame = f.read(incl_len)
            if len(raw_frame) < incl_len:
                break

            fc_int, src, dst, bssid = _parse_80211(raw_frame, has_radiotap)

            yield Frame(
                index=      index,
                ts_sec=     ts_sec,
                ts_usec=    ts_usec,
                orig_len=   orig_len,
                incl_len=   incl_len,
                frame_type= _parse_frame_control(fc_int),
                frame_ctrl= fc_int,
                src_mac=    src,
                dst_mac=    dst,
                bssid=      bssid,
                radiotap=   has_radiotap,
                source_fmt= "pcap",
            )

            index += 1
            if limit and index >= limit:
                break


# -----------------------------------------------------------------
# PCAPNG reader
# -----------------------------------------------------------------

def _read_pcapng_block(f, endian: str) -> tuple[int, bytes] | None:
    """
    Read one PCAPNG block from the current file position.
    Returns (block_type, block_body) or None on EOF.

    Block layout:
        [Block Type: 4B] [Block Total Length: 4B] [Body ...] [Block Total Length: 4B]
    """
    hdr = f.read(8)
    if len(hdr) < 8:
        return None

    block_type, total_len = struct.unpack(endian + "II", hdr)

    if total_len < 12 or total_len % 4 != 0:
        # Malformed block — skip to avoid infinite loop
        return None

    body_len  = total_len - 12          # 8 (header) + 4 (trailing length field)
    body      = f.read(body_len)
    f.read(4)                           # trailing Block Total Length (skip)

    return block_type, body


def _iter_pcapng(filepath: str, limit: int) -> Generator[Frame, None, None]:
    with open(filepath, "rb") as f:

        # --- Read SHB to determine byte order ---
        shb_type_raw = f.read(4)
        if len(shb_type_raw) < 4:
            raise ValueError("File too small for a PCAPNG SHB.")

        # SHB total length
        shb_len_raw = f.read(4)
        shb_total   = struct.unpack("<I", shb_len_raw)[0]

        # Byte-order magic is at offset 8 within the SHB
        bom_raw = f.read(4)
        bom     = struct.unpack("<I", bom_raw)[0]

        if bom == SHB_BYTE_ORDER_MAGIC:
            endian = "<"
        elif bom == 0x4D3C2B1A:
            endian = ">"
        else:
            raise ValueError(f"Invalid SHB byte-order magic: 0x{bom:08X}")

        # Skip rest of SHB body + trailing length field
        # Already consumed: 4 (block type) + 4 (total len) + 4 (BOM) = 12 bytes
        remaining = shb_total - 12
        f.read(remaining)

        # --- Track link types per interface (IDB index → linktype) ---
        interfaces: list[int] = []
        index = 0

        while True:
            block = _read_pcapng_block(f, endian)
            if block is None:
                break

            block_type, body = block

            # Interface Description Block — register link type
            if block_type == BT_IDB:
                if len(body) >= 2:
                    linktype = struct.unpack(endian + "H", body[:2])[0]
                else:
                    linktype = 0
                interfaces.append(linktype)
                continue

            # Enhanced Packet Block (most common)
            if block_type == BT_EPB:
                if len(body) < 20:
                    continue

                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    endian + "IIIII", body[:20]
                )
                ts_combined = (ts_high << 32) | ts_low
                ts_sec  = ts_combined // 1_000_000
                ts_usec = ts_combined  % 1_000_000

                raw_frame = body[20 : 20 + cap_len]

                linktype     = interfaces[iface_id] if iface_id < len(interfaces) else 0
                has_radiotap = (linktype == LINKTYPE_IEEE802_11_RADIOTAP)

                fc_int, src, dst, bssid = _parse_80211(raw_frame, has_radiotap)

                yield Frame(
                    index=      index,
                    ts_sec=     ts_sec,
                    ts_usec=    ts_usec,
                    orig_len=   orig_len,
                    incl_len=   cap_len,
                    frame_type= _parse_frame_control(fc_int),
                    frame_ctrl= fc_int,
                    src_mac=    src,
                    dst_mac=    dst,
                    bssid=      bssid,
                    radiotap=   has_radiotap,
                    source_fmt= "pcapng",
                )
                index += 1
                if limit and index >= limit:
                    break
                continue

            # Simple Packet Block (no timestamps)
            if block_type == BT_SPB:
                if len(body) < 4:
                    continue

                orig_len  = struct.unpack(endian + "I", body[:4])[0]
                raw_frame = body[4:]
                cap_len   = len(raw_frame)

                linktype     = interfaces[0] if interfaces else 0
                has_radiotap = (linktype == LINKTYPE_IEEE802_11_RADIOTAP)

                fc_int, src, dst, bssid = _parse_80211(raw_frame, has_radiotap)

                yield Frame(
                    index=      index,
                    ts_sec=     0,
                    ts_usec=    0,
                    orig_len=   orig_len,
                    incl_len=   cap_len,
                    frame_type= _parse_frame_control(fc_int),
                    frame_ctrl= fc_int,
                    src_mac=    src,
                    dst_mac=    dst,
                    bssid=      bssid,
                    radiotap=   has_radiotap,
                    source_fmt= "pcapng",
                )
                index += 1
                if limit and index >= limit:
                    break
                continue

            # Obsolete Packet Block
            if block_type == BT_OPB:
                if len(body) < 16:
                    continue

                iface_id, drops, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    endian + "HHHIII", body[:18]
                )
                ts_combined = (ts_high << 32) | ts_low
                ts_sec  = ts_combined // 1_000_000
                ts_usec = ts_combined  % 1_000_000

                raw_frame = body[18 : 18 + cap_len]

                linktype     = interfaces[iface_id] if iface_id < len(interfaces) else 0
                has_radiotap = (linktype == LINKTYPE_IEEE802_11_RADIOTAP)

                fc_int, src, dst, bssid = _parse_80211(raw_frame, has_radiotap)

                yield Frame(
                    index=      index,
                    ts_sec=     ts_sec,
                    ts_usec=    ts_usec,
                    orig_len=   orig_len,
                    incl_len=   cap_len,
                    frame_type= _parse_frame_control(fc_int),
                    frame_ctrl= fc_int,
                    src_mac=    src,
                    dst_mac=    dst,
                    bssid=      bssid,
                    radiotap=   has_radiotap,
                    source_fmt= "pcapng",
                )
                index += 1
                if limit and index >= limit:
                    break
                continue

            # Any other block type (NRB, ISB, custom…) — skip silently


# -----------------------------------------------------------------
# Public API — auto-detecting entry point
# -----------------------------------------------------------------

def iter_frames(filepath: str, limit: int = 0) -> Generator[Frame, None, None]:
    """
    Yield Frame objects from a .pcap or .pcapng file.
    Format is detected automatically.
    Set limit=0 for no limit.
    """
    fmt = _detect_format(filepath)
    if fmt == "pcap":
        yield from _iter_pcap(filepath, limit)
    else:
        yield from _iter_pcapng(filepath, limit)


# -----------------------------------------------------------------
# CLI
# -----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parse .pcap or .pcapng files captured by the ESP32. Format is auto-detected."
    )
    parser.add_argument("--file",   required=True, help="Path to .pcap or .pcapng file")
    parser.add_argument("--limit",  type=int, default=0, help="Max frames to read (0 = all)")
    parser.add_argument("--export", default=None,        help="Export frames to JSON")
    parser.add_argument("--filter", default=None,
                        help="Show only frames matching this type substring (e.g. 'Beacon')")
    args = parser.parse_args()

    fmt = _detect_format(args.file)
    print(f"\n[*] File   : {args.file}")
    print(f"[*] Format : {fmt.upper()}")

    frames = list(iter_frames(args.file, limit=args.limit))

    if args.filter:
        frames = [fr for fr in frames if args.filter.lower() in fr.frame_type.lower()]

    print(f"[*] Frames : {len(frames)}\n")

    print(f"  {'#':<5} {'Type':<25} {'Src MAC':<20} {'Dst MAC':<20} {'BSSID':<20} {'Size':>6}")
    print("  " + "-" * 100)
    for fr in frames[:200]:
        print(
            f"  {fr.index:<5} {fr.frame_type:<25} {fr.src_mac:<20} "
            f"{fr.dst_mac:<20} {fr.bssid:<20} {fr.orig_len:>5}B"
        )

    if len(frames) > 200:
        print(f"\n  ... and {len(frames) - 200} more frames (use --export for full output)")

    if args.export:
        with open(args.export, "w") as out:
            json.dump([asdict(fr) for fr in frames], out, indent=2)
        print(f"\n[+] Exported {len(frames)} frames → {args.export}")


if __name__ == "__main__":
    main()
