<div align="center">

# 📡 ESP32 WiFi Security Research Lab

**Passive IEEE 802.11 analysis platform built on ESP32 — from raw firmware capture to interactive HTML reports**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.x-E7352C?style=flat-square&logo=espressif&logoColor=white)](https://docs.espressif.com/projects/esp-idf/en/latest/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![Scope](https://img.shields.io/badge/Scope-Educational-blue?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

<br/>

*A complete, zero-dependency analysis pipeline for 802.11 frame captures — from ESP32 monitor-mode firmware to self-contained HTML dashboards.*

</div>

---

> ⚠️ **Legal & Ethical Notice** — This project is developed strictly for educational and research purposes within controlled environments. All experimentation is conducted exclusively on hardware owned by the developer, networks under the developer's direct control, or systems for which explicit written permission has been obtained. This repository does **not** endorse, support, or facilitate unauthorized access to networks, disruption of communications, or any activity prohibited by applicable law. Users are solely responsible for ensuring compliance with all applicable regulations.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Pipeline](#-pipeline)
- [System Architecture](#-system-architecture)
- [Analyzer Suite](#-analyzer-suite)
- [Technical Specifications](#-technical-specifications)
- [Hardware Requirements](#-hardware-requirements)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [Repository Structure](#-repository-structure)
- [Roadmap](#-roadmap)
- [Documentation](#-documentation)
- [Attribution](#-attribution)
- [License](#-license)

---

## 🔭 Overview

This repository is a hands-on research adaptation of [`esp32-wifi-penetration-tool`](https://github.com/risinek/esp32-wifi-penetration-tool), repurposed exclusively for passive IEEE 802.11 analysis and protocol study.

The project covers the **full stack** from embedded firmware to data visualization:

- **Firmware layer** — ESP32 in promiscuous (monitor) mode, capturing raw 802.11 frames
- **Binary parsing layer** — Zero-dependency Python parser for `.pcap` and `.pcapng` files, including full radiotap header and beacon body extraction
- **Analysis layer** — Serial log parser with frame classification, channel stats, and top-talker tracking
- **Visualization layer** — Self-contained HTML report generator with 6 interactive Chart.js visualizations

**Core study areas:**

| Area | Topics Covered |
|---|---|
| 802.11 Protocol | Frame types/subtypes, beacon body, IEs, capability flags |
| RF Analysis | RSSI measurement, channel mapping, data rate distribution |
| Embedded Systems | ESP-IDF, promiscuous mode API, `wifi_promiscuous_pkt_t` |
| Binary Formats | PCAP global header, PCAPNG block structure, radiotap bitmap walking |
| Encryption Detection | RSN IE (WPA2), vendor IE OUI `00:50:F2:01` (WPA), capability Privacy bit |

---

## ⚙️ Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ESP32 Hardware                               │
│         Monitor Mode  ·  esp_wifi_set_promiscuous(true)             │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
          ┌────────────┴─────────────┐
          │                          │
          ▼                          ▼
  Serial Monitor Log          .pcap / .pcapng File
  (idf.py monitor)            (direct capture output)
          │                          │
          ▼                          ▼
  wifi_analyzer.py          pcap_parser.py
  ·  [FRAME] / [BEACON]     ·  Auto format detection
     regex parsing           ·  Radiotap header parsing
  ·  Frame classification    ·  RSSI, channel, data rate
  ·  Channel/RSSI stats      ·  Beacon body → SSID, encryption
  ·  Top talker tracking     ·  Networks table with avg RSSI
          │                          │
          └────────────┬─────────────┘
                       │
                  results.json / frames.json
                       │
                       ▼
              report_generator.py
              ·  Auto-detects input format
              ·  6 Chart.js visualizations
              ·  Networks table (SSID, BSSID, encryption)
              ·  Zero dependencies — runs in any browser
                       │
                       ▼
                  report.html  📊
```

---

## 🏗️ System Architecture

```
                    ┌──────────────────────────────┐
                    │         ESP32 Device          │
                    │   (Embedded Firmware Layer)   │
                    └─────────────┬────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
│   WiFi Scanner   │   │  Packet Sniffer  │   │  Control Interface   │
│  (802.11 scan)   │   │ (Monitor Mode)   │   │   (Local Web UI)     │
└────────┬─────────┘   └────────┬─────────┘   └──────────┬───────────┘
         │                      │                        │
         └──────────────────────┴────────────────────────┘
                                │
              ┌─────────────────┴─────────────────┐
              │                                   │
   ┌──────────────────────┐         ┌──────────────────────────┐
   │   Frame Processing   │         │    Data Export Layer     │
   │  (802.11 parsing)    │         │  (Serial log / PCAP/NG)  │
   └──────────────────────┘         └──────────────────────────┘
                                               │
              ┌────────────────────────────────┴───────────────────────────────┐
              │                                                                 │
   ┌──────────────────────┐                               ┌──────────────────────────┐
   │   wifi_analyzer.py   │                               │    pcap_parser.py        │
   │  Regex-based parser  │                               │  Binary PCAP/NG parser   │
   │  for serial logs     │                               │  + radiotap + beacons    │
   └──────────┬───────────┘                               └──────────┬───────────────┘
              │                                                       │
              └───────────────────────┬───────────────────────────────┘
                                      │
                           ┌──────────────────────┐
                           │  report_generator.py  │
                           │  HTML dashboard       │
                           └──────────────────────┘
```

---

## 🛠️ Analyzer Suite

The `analyzer/` directory contains three independent Python modules. No external dependencies — pure standard library.

### `wifi_analyzer.py` — Serial Log Parser

Parses `[FRAME]` and `[BEACON]` lines from the ESP32 serial monitor output.

```
[FRAME]  type=0x80 src=AA:BB:CC:DD:EE:FF dst=FF:FF:FF:FF:FF:FF rssi=-65 ch=6
[BEACON] ssid=MyNetwork bssid=AA:BB:CC:DD:EE:FF ch=6 rssi=-72
```

**Extracts:** frame type/category, source/destination MACs, RSSI, channel, discovered networks.  
**Outputs:** terminal summary table + structured JSON for downstream tools.

---

### `pcap_parser.py` — Binary PCAP/PCAPNG Parser

Zero-dependency binary parser with automatic format detection from magic bytes.

**Format support:**

| Format | Detection | Block Types |
|---|---|---|
| Classic PCAP | `0xA1B2C3D4` magic | Global header + record headers |
| PCAPNG | `0x0A0D0D0A` (SHB) | SHB · IDB · EPB · SPB · OPB |

**Extracted per frame:**

| Field | Source | Notes |
|---|---|---|
| RSSI | Radiotap `DBM_SIGNAL` | Signed byte, dBm |
| Channel | Radiotap `CHANNEL` | Freq (MHz) → channel lookup |
| Data Rate | Radiotap `RATE` | × 0.5 Mbps |
| SSID | Beacon IE tag 0 | UTF-8, `<hidden>` if empty |
| Encryption | RSN IE / vendor IE / cap flags | WPA2 / WPA / WEP / Open |
| Network Type | Capability ESS/IBSS bits | Infrastructure / Ad-Hoc |
| Beacon Interval | Beacon fixed params | milliseconds |
| Src/Dst/BSSID | 802.11 MAC header | |

---

### `report_generator.py` — HTML Dashboard Generator

Accepts JSON from either of the two parsers above (auto-detected). Produces a single self-contained `.html` file with no external dependencies at runtime.

**Visualizations included:**

| Chart | Type | Data |
|---|---|---|
| Frames per Channel | Bar | 802.11 channel activity |
| Frame Categories | Doughnut | Management / Control / Data split |
| Frame Type Breakdown | Bar | Top 12 subtypes |
| RSSI Distribution | Bar | 5 dBm histogram buckets |
| Data Rate Distribution | Bar | PHY layer Mbps breakdown |
| Top Transmitters | Bar | Most active MAC addresses |

Plus a **networks table** with: SSID · BSSID · Channel · RSSI min/avg/max · Encryption (colour-coded) · Network type · Frame count.

---

## 📊 Technical Specifications

| Parameter | Value |
|---|---|
| **Target Hardware** | ESP32-WROOM-32 |
| **Firmware Framework** | ESP-IDF v5.x |
| **Capture Mode** | Promiscuous (monitor) mode |
| **Supported Formats** | `.pcap`, `.pcapng`, ESP32 serial log |
| **Parser Dependencies** | None (Python stdlib only) |
| **Minimum Python** | 3.10+ |
| **Report Format** | Self-contained HTML (Chart.js via CDN) |
| **Frequency Bands** | 2.4 GHz (CH 1–14) · 5 GHz (CH 36–165) |
| **RSSI Sensitivity** | −97 dBm (ESP32 datasheet) |
| **Radiotap Fields** | TSFT · Flags · Rate · Channel · dBm Signal · Antenna |
| **Beacon IE Tags** | 0 (SSID) · 1 (Rates) · 3 (DS Params) · 48 (RSN) · 221 (Vendor) |

---

## 🔩 Hardware Requirements

| Component | Specification | Notes |
|---|---|---|
| Microcontroller | ESP32-WROOM-32 | WROOM-32D or WROOM-32U also work |
| USB Cable | Micro-USB, data-capable | Charge-only cables won't expose serial |
| Power Supply | 5V via USB or external 3.3V | External supply for standalone operation |
| Flash Storage | 4 MB (built-in) | Sufficient for firmware + SPIFFS |
| Host Machine | Any OS with Python 3.10+ | For running the analyzer suite |

---

## 🚀 Getting Started

### 1. Flash the Firmware

```bash
# Install ESP-IDF (see docs/setup_guide.md for full instructions)
. ~/esp/esp-idf/export.sh

# Clone the upstream firmware
git clone https://github.com/risinek/esp32-wifi-penetration-tool.git
cd esp32-wifi-penetration-tool

idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash
```

### 2. Capture Data

```bash
# Save serial output to file
idf.py -p /dev/ttyUSB0 monitor | tee monitor.log
# Ctrl+] to stop
```

### 3. Run the Analyzer

```bash
cd analyzer/

# No pip install needed — pure stdlib
python3 wifi_analyzer.py --log ../monitor.log --export results.json
python3 report_generator.py --input results.json --output report.html

# Open report.html in any browser
```

### 4. Or Parse a PCAP/PCAPNG Directly

```bash
python3 pcap_parser.py --file capture.pcapng --export frames.json
python3 report_generator.py --input frames.json --output report.html
```

---

## 💻 Usage

### `wifi_analyzer.py`

```
python3 wifi_analyzer.py --log <file>            Parse a serial monitor log
                          --export <file.json>    Export results to JSON
```

### `pcap_parser.py`

```
python3 pcap_parser.py --file <file>             Auto-detects .pcap or .pcapng
                        --export <file.json>      Export enriched frames + summary
                        --filter <type>           Filter by frame type substring
                        --limit <n>               Cap frames read (0 = all)
                        --summary-only            Skip per-frame table
```

### `report_generator.py`

```
python3 report_generator.py --input <file.json>  Auto-detects input format
                             --output <file.html> Output HTML report (default: report.html)
```

---

## 📁 Repository Structure

```
ESP32-WiFi-Security-Research-Lab/
│
├── analyzer/                        # Python analysis suite (stdlib only)
│   ├── wifi_analyzer.py             # Serial log parser
│   ├── pcap_parser.py               # Binary PCAP/PCAPNG parser + radiotap
│   └── report_generator.py          # Self-contained HTML report generator
│
├── docs/                            # Technical documentation
│   ├── 802_11_notes.md              # IEEE 802.11 protocol study notes
│   └── setup_guide.md               # ESP-IDF environment setup guide
│
├── .github/
│   ├── workflows/
│   │   └── lint.yml                 # Python syntax check on push
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
│
├── CHANGELOG.md                     # Version history and learning milestones
├── CONTRIBUTING.md                  # Contribution guidelines
├── requirements.txt                 # Python version constraint + optional deps
├── LICENSE                          # MIT
└── README.md
```

---

## 🗺️ Roadmap

| Status | Feature |
|---|---|
| ✅ Done | Serial log parser (`wifi_analyzer.py`) |
| ✅ Done | Binary PCAP/PCAPNG parser with radiotap + beacon extraction |
| ✅ Done | HTML report generator with 6 Chart.js visualizations |
| ✅ Done | Auto-format detection (`.pcap` vs `.pcapng`, input JSON type) |
| 🔄 In progress | Modular firmware refactor with cleaner component separation |
| 📋 Planned | Python channel-hopping controller for multi-channel captures |
| 📋 Planned | Wireshark `.pcapng` live export pipeline integration |
| 📋 Planned | Jupyter notebook for interactive PCAP analysis |
| 📋 Planned | Vendor OUI lookup (MAC → manufacturer name) |

---

## 📚 Documentation

Full technical notes are in the [`docs/`](docs/) folder:

- [`docs/802_11_notes.md`](docs/802_11_notes.md) — Deep-dive on frame structure, radiotap format, encryption detection logic, PCAP vs PCAPNG, and RSSI reference table
- [`docs/setup_guide.md`](docs/setup_guide.md) — Step-by-step ESP-IDF installation and flashing guide for Linux, macOS, and Windows

---

## 🔗 Attribution

This project is a learning-focused adaptation of:

> **esp32-wifi-penetration-tool** by [@risinek](https://github.com/risinek)  
> https://github.com/risinek/esp32-wifi-penetration-tool

Full credit for the original firmware implementation belongs to the original author. This repository is an independent educational adaptation and is not affiliated with or endorsed by the original project.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full terms.

---

## 🎓 Academic Context

This project is part of a personal learning path in **Telecommunications Engineering** at the University of Granada, focused on:

- Wireless communication systems (IEEE 802.11)
- Embedded systems programming (ESP32 / ESP-IDF)
- Network packet structure and binary protocol analysis
- RF signal characterisation and passive monitoring

It is intended to demonstrate practical, hands-on competency in low-level networking and embedded firmware development — not to be deployed in any production or adversarial context.

---

<div align="center">

**If this project is useful for your studies or research, consider leaving a ⭐**

</div>
