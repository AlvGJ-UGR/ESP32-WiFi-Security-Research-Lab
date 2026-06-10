"""
analyzer/frame_parser.py
-------------------------
Low-level 802.11 frame classification and metadata extractor.

Provides a clean interface over raw Scapy Dot11 layers so the rest of
the analyzer never imports Scapy directly.
"""

from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
    from scapy.all import Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Deauth
    from scapy.all import Dot11Disas, Dot11Elt
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# ── frame type constants (IEEE 802.11-2020) ──────────────────────────────────
MGMT_SUBTYPES = {
    0:  "Association Request",
    1:  "Association Response",
    2:  "Reassociation Request",
    3:  "Reassociation Response",
    4:  "Probe Request",
    5:  "Probe Response",
    8:  "Beacon",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
}

CTRL_SUBTYPES = {
    8:  "Block Ack Request",
    9:  "Block Ack",
    10: "PS-Poll",
    11: "RTS",
    12: "CTS",
    13: "ACK",
}

DATA_SUBTYPES = {
    0: "Data",
    4: "Null (no data)",
    8: "QoS Data",
}


@dataclass
class FrameInfo:
    """Parsed metadata for a single 802.11 frame."""
    timestamp:   float
    frame_type:  str          # "Management", "Control", "Data", "Unknown"
    subtype:     str
    src_mac:     str
    dst_mac:     str
    bssid:       str
    ssid:        Optional[str] = None
    channel:     Optional[int] = None
    seq_num:     Optional[int] = None
    raw_bytes:   int           = 0
    flags:       dict          = field(default_factory=dict)


def classify_frame(pkt) -> Optional[FrameInfo]:
    """
    Parse a Scapy packet into a FrameInfo.

    Returns None if the packet has no Dot11 layer.
    """
    if not SCAPY_OK:
        raise ImportError("scapy is required for frame parsing")

    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt.getlayer(Dot11)
    ts    = float(pkt.time)
    ftype = dot11.type
    fsub  = dot11.subtype

    # Classify type
    if ftype == 0:
        type_str = "Management"
        sub_str  = MGMT_SUBTYPES.get(fsub, f"Management-{fsub}")
    elif ftype == 1:
        type_str = "Control"
        sub_str  = CTRL_SUBTYPES.get(fsub, f"Control-{fsub}")
    elif ftype == 2:
        type_str = "Data"
        sub_str  = DATA_SUBTYPES.get(fsub, f"Data-{fsub}")
    else:
        type_str = "Unknown"
        sub_str  = f"Type{ftype}-Sub{fsub}"

    # SSID (Beacons and Probe Responses)
    ssid = None
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        elt = pkt.getlayer(Dot11Elt)
        if elt:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                ssid = "<decode-error>"

    # Channel
    channel = None
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and len(elt.info) >= 1:
            channel = elt.info[0]
            break
        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None

    # Flags
    flags = {}
    if pkt.haslayer(Dot11Deauth):
        flags["reason"] = pkt.getlayer(Dot11Deauth).reason
    if pkt.haslayer(Dot11Auth):
        flags["algo"] = pkt.getlayer(Dot11Auth).algo

    return FrameInfo(
        timestamp  = ts,
        frame_type = type_str,
        subtype    = sub_str,
        src_mac    = (dot11.addr2 or "").upper(),
        dst_mac    = (dot11.addr1 or "").upper(),
        bssid      = (dot11.addr3 or "").upper(),
        ssid       = ssid,
        channel    = channel,
        seq_num    = dot11.SC >> 4 if dot11.SC is not None else None,
        raw_bytes  = len(pkt),
        flags      = flags,
    )


def frame_type_distribution(frames: list[FrameInfo]) -> dict[str, int]:
    """Return a counter dict: frame_type → count."""
    dist: dict[str, int] = {}
    for f in frames:
        dist[f.frame_type] = dist.get(f.frame_type, 0) + 1
    return dist


def subtype_distribution(frames: list[FrameInfo]) -> dict[str, int]:
    """Return a counter dict: subtype → count."""
    dist: dict[str, int] = {}
    for f in frames:
        dist[f.subtype] = dist.get(f.subtype, 0) + 1
    return dict(sorted(dist.items(), key=lambda x: x[1], reverse=True))
