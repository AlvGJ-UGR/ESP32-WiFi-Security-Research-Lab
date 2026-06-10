# Changelog

All notable changes and learning milestones in this project are documented here.

Format loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### In Progress
- Python visualization dashboard for offline PCAP analysis
- Modular firmware refactor with cleaner component separation
- Wireshark export pipeline for `.pcapng` live analysis

---

## [0.3.0] — Analyzer Suite Complete

### Added
- `analyzer/report_generator.py` — generates self-contained HTML reports from JSON output
  - 5 inline Chart.js visualizations: channel distribution, frame categories (doughnut),
    frame type breakdown, RSSI histogram, top transmitters
  - Networks table with SSID, BSSID, channel, RSSI range, encryption type, network type
  - Capture duration stat card
  - Data rate distribution chart (PHY layer Mbps breakdown)
  - Dark-themed, zero-dependency HTML output (no server required)
- Auto-format detection in `report_generator.py` — no `--mode` flag required for new format

### Changed
- `report_generator.py` now accepts both enriched dict format and legacy list format
  from `pcap_parser.py`, with automatic detection based on JSON structure

### Learned
- Chart.js API for dynamic chart rendering from Python-generated JSON
- HTML/CSS design patterns for technical dashboards
- How to make a fully self-contained single-file HTML report

---

## [0.2.0] — PCAP/PCAPNG Binary Parsing

### Added
- `analyzer/pcap_parser.py` — zero-dependency binary parser for `.pcap` and `.pcapng` files
  - Auto-detects file format from magic bytes (no flag needed)
  - Full radiotap header parsing: RSSI (dBm), channel, frequency, data rate
  - Beacon/Probe Response body parsing: SSID, beacon interval, encryption (WPA2/WPA/WEP/Open),
    network type (Infrastructure / Ad-Hoc)
  - PCAPNG block support: SHB, IDB, EPB, SPB, OPB
  - Per-capture summary: RSSI histogram, channel distribution, top talkers,
    data rate distribution, network table with avg/min/max RSSI
  - `--filter`, `--limit`, `--summary-only`, `--export` CLI flags

### Fixed
- SHB offset calculation bug in PCAPNG reader (4-byte misalignment causing all
  subsequent blocks to be misread)

### Learned
- PCAP global header and record header binary format (`struct` unpacking)
- PCAPNG block structure: type + length-prefixed body + trailing length
- Radiotap header layout and presence bitmap walking
- IEEE 802.11 frame control field: type (2 bits) + subtype (4 bits) decoding
- 802.11 Information Element (tagged parameter) structure: tag + length + data
- RSN IE (tag 48) vs WPA vendor IE (tag 221, OUI 00:50:F2:01) for encryption detection
- Frequency → channel mapping for 2.4 GHz and 5 GHz bands

---

## [0.1.0] — Serial Log Analyzer

### Added
- `analyzer/wifi_analyzer.py` — parses ESP32 serial monitor logs
  - Regex-based `[FRAME]` and `[BEACON]` line parser
  - Frame classification: management / control / data categories
  - IEEE 802.11 frame type lookup table (0x00–0xC0)
  - Per-capture stats: total frames, avg/min/max RSSI, channel distribution,
    top talkers, discovered networks
  - `--export` flag to dump structured JSON for downstream tools
- Initial `analyzer/` folder structure

### Learned
- Python `struct`, `re`, `argparse`, `collections.defaultdict` for binary/text parsing
- IEEE 802.11 frame type and subtype encoding
- How ESP32 serial monitor output is structured in ESP-IDF
- RSSI values and what signal strength ranges mean in practice
  (> -50 dBm excellent, -50 to -70 good, -70 to -85 fair, < -85 poor)

---

## [0.0.1] — Project Initialization

### Added
- Repository created as educational fork reference of
  [esp32-wifi-penetration-tool](https://github.com/risinek/esp32-wifi-penetration-tool)
- `README.md` with project overview, legal notice, architecture diagram,
  hardware requirements, and learning objectives
- `LICENSE` (MIT, consistent with upstream)
- `docs/` folder initialized for technical notes

### Learned
- ESP32-WROOM-32 hardware capabilities and limitations
- ESP-IDF build system: `idf.py build / flash / monitor`
- Difference between monitor mode and managed mode in WiFi adapters
- Why ESP32 can do passive packet capture (raw 802.11 frame access via `esp_wifi_set_promiscuous`)
