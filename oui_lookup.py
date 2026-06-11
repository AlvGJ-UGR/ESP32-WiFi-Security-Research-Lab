"""
oui_lookup.py
-------------
Resolves MAC address prefixes (OUI — Organizationally Unique Identifier)
to manufacturer names without any external API calls or pip dependencies.

The module ships with a curated OUI table covering the most common
manufacturers seen in 802.11 captures. For the full IEEE registry
(~35,000 entries) use the --update-db flag to download it once.

Usage (standalone):
    python oui_lookup.py AA:BB:CC:DD:EE:FF
    python oui_lookup.py --update-db          # download full IEEE registry
    python oui_lookup.py --stats capture.json # annotate a frames JSON

Usage (as a module):
    from oui_lookup import resolve, resolve_many
    print(resolve("AA:BB:CC:DD:EE:FF"))       # → "Apple, Inc."
"""

import re
import os
import json
import argparse
import urllib.request
from pathlib import Path
from functools import lru_cache


# ─────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────

_HERE     = Path(__file__).parent
_DB_PATH  = _HERE / "oui_db.json"          # downloaded full database (optional)
_IEEE_URL = "https://standards-oui.ieee.org/oui/oui.txt"


# ─────────────────────────────────────────────────────────────────
# Curated built-in table (~120 most common in WiFi captures)
# ─────────────────────────────────────────────────────────────────

_BUILTIN: dict[str, str] = {
    # Apple
    "000393": "Apple, Inc.",
    "000A27": "Apple, Inc.",
    "000A95": "Apple, Inc.",
    "001124": "Apple, Inc.",
    "001451": "Apple, Inc.",
    "0016CB": "Apple, Inc.",
    "001E52": "Apple, Inc.",
    "001EC2": "Apple, Inc.",
    "0021E9": "Apple, Inc.",
    "002312": "Apple, Inc.",
    "002500": "Apple, Inc.",
    "0026B9": "Apple, Inc.",
    "0050E4": "Apple, Inc.",
    "60D9C7": "Apple, Inc.",
    "8C2DAA": "Apple, Inc.",
    "A4C361": "Apple, Inc.",
    "DC9B9C": "Apple, Inc.",
    "F0DBE2": "Apple, Inc.",

    # Samsung
    "001599": "Samsung Electronics",
    "002339": "Samsung Electronics",
    "0024E9": "Samsung Electronics",
    "002566": "Samsung Electronics",
    "0026E2": "Samsung Electronics",
    "38AA3C": "Samsung Electronics",
    "40B395": "Samsung Electronics",
    "6C2F2C": "Samsung Electronics",
    "8C77B3": "Samsung Electronics",
    "B47443": "Samsung Electronics",

    # Intel (WiFi adapters)
    "001111": "Intel Corporation",
    "001320": "Intel Corporation",
    "001E64": "Intel Corporation",
    "001E67": "Intel Corporation",
    "0021D8": "Intel Corporation",
    "00248D": "Intel Corporation",
    "00262D": "Intel Corporation",
    "7085C2": "Intel Corporation",
    "8086F2": "Intel Corporation",
    "A4C494": "Intel Corporation",

    # Cisco / Linksys
    "000142": "Cisco Systems",
    "000143": "Cisco Systems",
    "00016C": "Cisco Systems",
    "001A2F": "Cisco Systems",
    "001D45": "Cisco Systems",
    "001E13": "Cisco Systems",
    "001E49": "Cisco Systems",
    "0021A0": "Cisco Systems",
    "002255": "Cisco Systems",
    "C84B44": "Cisco Linksys",

    # TP-Link
    "1C3BF3": "TP-Link Technologies",
    "3C46D8": "TP-Link Technologies",
    "50C7BF": "TP-Link Technologies",
    "544A16": "TP-Link Technologies",
    "5C628B": "TP-Link Technologies",
    "74EA3A": "TP-Link Technologies",
    "8CAAB5": "TP-Link Technologies",
    "90F652": "TP-Link Technologies",
    "B0487A": "TP-Link Technologies",
    "C46E1F": "TP-Link Technologies",
    "E8DE27": "TP-Link Technologies",
    "F81A67": "TP-Link Technologies",

    # Netgear
    "001E2A": "Netgear",
    "00224B": "Netgear",
    "0026F2": "Netgear",
    "20E52A": "Netgear",
    "2CB05D": "Netgear",
    "4C60DE": "Netgear",
    "9C3DCF": "Netgear",
    "A040A0": "Netgear",
    "C03F0E": "Netgear",
    "E091F5": "Netgear",

    # Huawei
    "001E10": "Huawei Technologies",
    "002568": "Huawei Technologies",
    "0C37DC": "Huawei Technologies",
    "286ED4": "Huawei Technologies",
    "30D17E": "Huawei Technologies",
    "3C47C9": "Huawei Technologies",
    "405BD8": "Huawei Technologies",
    "48DB50": "Huawei Technologies",
    "54A51B": "Huawei Technologies",
    "6C8D37": "Huawei Technologies",
    "90E7C4": "Huawei Technologies",
    "B8BC1B": "Huawei Technologies",
    "D46AA8": "Huawei Technologies",

    # Xiaomi
    "286C07": "Xiaomi Communications",
    "34CE00": "Xiaomi Communications",
    "58DDC7": "Xiaomi Communications",
    "64B473": "Xiaomi Communications",
    "74606D": "Xiaomi Communications",
    "8C97EA": "Xiaomi Communications",
    "9C99A0": "Xiaomi Communications",
    "AC2391": "Xiaomi Communications",
    "F48B32": "Xiaomi Communications",
    "FC64BA": "Xiaomi Communications",

    # Google
    "3C5AB4": "Google (Nest/Chromecast)",
    "54607E": "Google (Nest/Chromecast)",
    "6C AD F8": "Google (Nest/Chromecast)",
    "A47733": "Google (Nest/Chromecast)",
    "F4F5D8": "Google (Nest/Chromecast)",
    "F8F1B6": "Google (Nest/Chromecast)",

    # Amazon
    "40B4CD": "Amazon Technologies",
    "44650D": "Amazon Technologies",
    "68370E": "Amazon Technologies",
    "74C246": "Amazon Technologies",
    "84D6D0": "Amazon Technologies",
    "A002DC": "Amazon Technologies",
    "F0272D": "Amazon Technologies",

    # Ubiquiti
    "002722": "Ubiquiti Networks",
    "04185A": "Ubiquiti Networks",
    "0418D6": "Ubiquiti Networks",
    "246895": "Ubiquiti Networks",
    "44D9E7": "Ubiquiti Networks",
    "687260": "Ubiquiti Networks",
    "788A20": "Ubiquiti Networks",
    "802AA8": "Ubiquiti Networks",
    "DC9FDB": "Ubiquiti Networks",
    "F09FC2": "Ubiquiti Networks",

    # ASUS
    "049226": "ASUSTeK Computer",
    "10BF48": "ASUSTeK Computer",
    "107B44": "ASUSTeK Computer",
    "1C872C": "ASUSTeK Computer",
    "2C56DC": "ASUSTeK Computer",
    "305A3A": "ASUSTeK Computer",
    "40167E": "ASUSTeK Computer",
    "50465D": "ASUSTeK Computer",
    "6045CB": "ASUSTeK Computer",
    "70659B": "ASUSTeK Computer",

    # Qualcomm / Atheros
    "00037F": "Atheros / Qualcomm",
    "001374": "Atheros / Qualcomm",
    "20A6CD": "Qualcomm",
    "8047BA": "Qualcomm",

    # Broadcom
    "001018": "Broadcom",
    "00904C": "Broadcom",
    "880FA1": "Broadcom",

    # Raspberry Pi
    "B827EB": "Raspberry Pi Foundation",
    "DC A6 32": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",

    # Espressif (ESP32 / ESP8266 devices)
    "240AC4": "Espressif Systems (ESP32)",
    "3C71BF": "Espressif Systems (ESP32)",
    "485519": "Espressif Systems (ESP8266)",
    "5CCF7F": "Espressif Systems (ESP8266)",
    "60019F": "Espressif Systems (ESP32)",
    "8CAAB5": "Espressif Systems",
    "A020A6": "Espressif Systems (ESP8266)",
    "BCDDC2": "Espressif Systems (ESP32)",
    "D8F15B": "Espressif Systems (ESP32)",
    "E89F6D": "Espressif Systems (ESP32)",
}


# ─────────────────────────────────────────────────────────────────
# Normalisation helpers
# ─────────────────────────────────────────────────────────────────

def _normalise_mac(mac: str) -> str:
    """Strip separators and uppercase. Returns 12-char hex string."""
    return re.sub(r"[:\-\.\s]", "", mac).upper()


def _oui_from_mac(mac: str) -> str:
    """Extract the 6-char OUI prefix from a MAC address."""
    return _normalise_mac(mac)[:6]


# ─────────────────────────────────────────────────────────────────
# Database management
# ─────────────────────────────────────────────────────────────────

def _load_db() -> dict[str, str]:
    """Load the downloaded IEEE OUI database if it exists."""
    if _DB_PATH.exists():
        try:
            with open(_DB_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def download_ieee_db(verbose: bool = True) -> int:
    """
    Download the full IEEE OUI registry and cache it locally.
    Returns the number of entries saved.

    The file is ~5 MB and contains ~35,000 OUI assignments.
    """
    if verbose:
        print(f"[*] Downloading IEEE OUI registry from {_IEEE_URL} ...")

    try:
        with urllib.request.urlopen(_IEEE_URL, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Download failed: {e}")
        return 0

    db: dict[str, str] = {}
    # Format: "XX-XX-XX   (hex)\t\tManufacturer Name"
    pattern = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$",
                         re.MULTILINE)
    for match in pattern.finditer(raw):
        oui  = match.group(1).replace("-", "")
        name = match.group(2).strip()
        db[oui] = name

    with open(_DB_PATH, "w") as f:
        json.dump(db, f, separators=(",", ":"))

    if verbose:
        print(f"[+] Saved {len(db):,} OUI entries to {_DB_PATH}")

    return len(db)


# Lazy-loaded full database
_FULL_DB: dict[str, str] | None = None

def _get_full_db() -> dict[str, str]:
    global _FULL_DB
    if _FULL_DB is None:
        _FULL_DB = _load_db()
    return _FULL_DB


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────

@lru_cache(maxsize=4096)
def resolve(mac: str) -> str:
    """
    Resolve a MAC address to a manufacturer name.

    Lookup order:
      1. Built-in curated table (~120 common manufacturers)
      2. Downloaded IEEE database (oui_db.json), if available
      3. Returns "Unknown" if not found

    Args:
        mac: MAC address in any common format
             ("AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "AABBCCDDEEFF")

    Returns:
        Manufacturer name string, or "Unknown (OUI: XXYYZZ)"
    """
    if not mac or "?" in mac:
        return "Unknown"

    try:
        oui = _oui_from_mac(mac)
    except Exception:
        return "Unknown"

    # Check built-in table first (fastest)
    if oui in _BUILTIN:
        return _BUILTIN[oui]

    # Check downloaded IEEE database
    full_db = _get_full_db()
    if full_db and oui in full_db:
        return full_db[oui]

    return f"Unknown (OUI: {oui[:2]}:{oui[2:4]}:{oui[4:6]})"


def resolve_many(macs: list[str]) -> dict[str, str]:
    """
    Resolve a list of MAC addresses.
    Returns a dict mapping each MAC to its manufacturer name.
    """
    return {mac: resolve(mac) for mac in macs}


def annotate_frames(frames: list[dict]) -> list[dict]:
    """
    Add 'src_vendor' and 'dst_vendor' fields to a list of frame dicts
    (as produced by pcap_parser.py --export).
    """
    for frame in frames:
        frame["src_vendor"] = resolve(frame.get("src_mac", ""))
        frame["dst_vendor"] = resolve(frame.get("dst_mac", ""))
    return frames


def top_vendors(frames: list[dict], n: int = 10) -> list[tuple[str, int]]:
    """
    Return the top N vendors by frame count from a list of frame dicts.
    """
    from collections import Counter
    counts: Counter = Counter()
    for frame in frames:
        vendor = resolve(frame.get("src_mac", ""))
        counts[vendor] += 1
    return counts.most_common(n)


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve MAC addresses to manufacturer names."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("mac", nargs="?",
                       help="Single MAC address to resolve")
    group.add_argument("--update-db", action="store_true",
                       help="Download the full IEEE OUI registry (~5 MB, ~35k entries)")
    group.add_argument("--stats", metavar="FILE",
                       help="Annotate a frames JSON file and print vendor statistics")
    parser.add_argument("--top", type=int, default=15,
                        help="Number of top vendors to show with --stats (default: 15)")
    args = parser.parse_args()

    if args.update_db:
        download_ieee_db(verbose=True)
        return

    if args.stats:
        print(f"[*] Loading {args.stats} ...")
        with open(args.stats) as f:
            data = json.load(f)

        # Accept both enriched format (dict with 'frames') and plain list
        frames = data["frames"] if isinstance(data, dict) and "frames" in data else data

        vendors = top_vendors(frames, n=args.top)
        db_size = len(_get_full_db())
        source  = f"IEEE DB ({db_size:,} entries)" if db_size else "built-in table"

        print(f"\n  OUI source: {source}")
        print(f"\n  {'Vendor':<40} {'Frames':>8}")
        print("  " + "─" * 50)
        for vendor, count in vendors:
            print(f"  {vendor:<40} {count:>8,}")
        print()
        return

    if args.mac:
        result = resolve(args.mac)
        oui    = _oui_from_mac(args.mac)
        db_size = len(_get_full_db())
        source  = "IEEE DB" if (db_size and oui in _get_full_db()) else \
                  "built-in" if oui in _BUILTIN else "not found"
        print(f"  MAC      : {args.mac.upper()}")
        print(f"  OUI      : {oui[:2]}:{oui[2:4]}:{oui[4:6]}")
        print(f"  Vendor   : {result}")
        print(f"  Source   : {source}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
