# Changelog

All notable changes and learning milestones are documented here.

---

## [Unreleased]

### In Progress
- Modular firmware refactor with sdkconfig presets

### Planned
- Jupyter notebook for interactive PCAP exploration
- Wireshark live-feed polish (USBPcap integration on Windows)

---

## [0.4.0] — Roadmap completion: OUI lookup · Streamlit dashboard · Wireshark export

### Added
- `analyzer/oui_lookup.py` — MAC address → manufacturer name resolution
  - Built-in table covering ~120 most common WiFi vendors
  - Optional full IEEE OUI registry download (~35,000 entries) via `--update-db`
  - `resolve()` / `resolve_many()` / `annotate_frames()` / `top_vendors()` public API
  - `--stats <frames.json>` CLI: vendor breakdown from any capture file
  - LRU cache for repeated lookups
- `analyzer/dashboard.py` — Streamlit live dashboard
  - 6 interactive Plotly charts (channel, category doughnut, frame types,
    RSSI histogram, data rates, top transmitters)
  - Networks table with vendor enrichment and encryption colour-coding
  - RSSI scatter over time (frame-level data)
  - Auto-refresh mode for live captures from the ESP32 HTTP endpoint
  - File upload, local path, or direct ESP32 URL as data sources
- `analyzer/wireshark_export.py` — Live Wireshark feed from the ESP32
  - **pipe** mode — FIFO named pipe streamed into Wireshark (Linux/macOS)
  - **stdout** mode — raw PCAP stream piped directly into Wireshark
  - **file** mode — periodic polling + timestamped saves + auto-open (all platforms)
  - `--open <file>` — one-click open any `.pcap` in Wireshark
  - Auto-detects Wireshark binary on Linux, macOS, and Windows
- `requirements.txt` — split into stdlib-only core vs. optional deps by feature
- `CHANGELOG.md`, `CONTRIBUTING.md`, `.gitignore` added

### Learned
- IEEE OUI registry format and binary structure parsing
- Streamlit session state and auto-refresh patterns
- Named FIFO pipes on POSIX systems for inter-process streaming
- PCAP record block structure for incremental append (ring-buffer diffing)
- Plotly Express vs Graph Objects for custom dark-theme charts

---

## [0.3.0] — HTML Report Generator

### Added
- `analyzer/report_generator.py` — self-contained HTML report from JSON output
  - 6 Chart.js visualizations + networks table (SSID, encryption, avg RSSI)
  - Auto-detects input format (enriched dict vs. legacy list)
  - Zero runtime dependencies — opens in any browser without a server

### Learned
- Chart.js 4.x configuration for dynamic data
- CSS custom properties and dark-theme dashboard design
- Self-contained single-file HTML pattern

---

## [0.2.0] — Binary PCAP/PCAPNG Parser

### Added
- `analyzer/pcap_parser.py` — zero-dependency binary parser
  - Auto format detection (`.pcap` magic `0xA1B2C3D4` vs PCAPNG SHB `0x0A0D0D0A`)
  - Full radiotap header parsing: RSSI, channel, frequency, data rate
  - Beacon/Probe Response body: SSID, encryption, beacon interval, network type
  - PCAPNG blocks: SHB, IDB, EPB, SPB, OPB

### Fixed
- SHB offset calculation bug (4-byte misalignment in PCAPNG reader)

### Learned
- PCAP global header and record header binary format (`struct` unpacking)
- Radiotap header bitmap field walking with natural alignment padding
- RSN IE (tag 48) vs vendor IE OUI `00:50:F2:01` for WPA/WPA2 detection
- Frequency → channel mapping for 2.4 GHz and 5 GHz bands

---

## [0.1.0] — Serial Log Analyzer

### Added
- `analyzer/wifi_analyzer.py` — ESP32 serial monitor log parser
  - `[FRAME]` / `[BEACON]` regex parsing
  - Frame classification (management / control / data)
  - RSSI stats, channel distribution, top talkers

### Learned
- IEEE 802.11 frame type/subtype encoding (FC bits 2–7)
- ESP-IDF serial monitor log structure
- RSSI signal strength reference ranges

---

## [0.0.1] — Project Initialization

### Added
- Repository as educational adaptation of esp32-wifi-penetration-tool
- Initial README, LICENSE, docs/ folder

### Learned
- ESP32 promiscuous mode API (`esp_wifi_set_promiscuous`)
- Difference between monitor mode and managed mode
- ESP-IDF build system basics
