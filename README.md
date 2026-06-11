# 📡 ESP32 WiFi Security Research Lab

**Passive IEEE 802.11 analysis platform — from ESP32 monitor-mode firmware to interactive HTML reports**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.1+-E7352C?style=flat-square&logo=espressif&logoColor=white)](https://docs.espressif.com/projects/esp-idf/en/latest/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)]()
[![Scope](https://img.shields.io/badge/Scope-Educational%20%2F%20Research-blue?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![University](https://img.shields.io/badge/UGR-Telecomunicaciones-red?style=flat-square)]()

<br/>

*A complete analysis pipeline for 802.11 captures —*  
*from ESP32 firmware with HTTP interface to self-contained HTML dashboards.*

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
- [Build & Flash](#-build--flash)
- [HTTP Control Interface](#-http-control-interface)
- [Python Analyzer](#-python-analyzer)
- [Features](#-features)
- [Repository Structure](#-repository-structure)
- [Roadmap](#-roadmap)
- [Documentation](#-documentation)
- [Attribution](#-attribution)
- [License](#-license)

---

## 🔭 Overview

This repository is a hands-on research adaptation of [`esp32-wifi-penetration-tool`](https://github.com/risinek/esp32-wifi-penetration-tool), repurposed exclusively for **passive IEEE 802.11 protocol analysis** and embedded systems study.

The project covers the full stack from firmware to visualization:

- **Firmware layer** — ESP32 in promiscuous (monitor) mode, captures raw 802.11 frames, writes them to an in-memory PCAP ring buffer, and serves them via a lightweight HTTP interface
- **Binary parsing layer** — Python parsers for `.pcap` and `.pcapng`, including full radiotap header and beacon body extraction
- **Analysis layer** — Frame classification, channel stats, AP enumeration, client activity, CSV export
- **Visualization layer** — Matplotlib plots and a self-contained HTML report generator

**Core study areas:**

| Area | Topics Covered |
|---|---|
| 802.11 Protocol | Frame types/subtypes, beacon body, Information Elements, capability flags |
| RF Analysis | RSSI measurement, channel mapping, data rate distribution, encryption detection |
| Embedded Systems | ESP-IDF, FreeRTOS tasks, promiscuous mode API, `wifi_promiscuous_pkt_t` |
| Networking | HTTP server on ESP32, PCAP ring buffer, Soft-AP configuration |
| Binary Formats | PCAP/PCAPNG structure, radiotap bitmap walking, 802.11 IE parsing |

---

## ⚙️ Pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│                         ESP32 Firmware                               │
│    Soft-AP  ·  Promiscuous sniffer  ·  PCAP ring buffer (512 KB)     │
└───────────────────────┬──────────────────────────────────────────────┘
                        │  HTTP GET /api/pcap/download
                        ▼
                  capture.pcap
                        │
           ┌────────────┴──────────────┐
           │                           │
           ▼                           ▼
   pcap_analyzer.py              pcap_parser.py
   · AP enumeration              · Auto-detects .pcap/.pcapng
   · Client activity             · Full radiotap parsing
   · Channel statistics          · RSSI, channel, data rate
   · CSV export                  · Beacon body → SSID, encryption
   · Matplotlib plots            · Networks table with avg RSSI
           │                           │
           └────────────┬──────────────┘
                        │
                 results.json / frames.json
                        │
                        ▼
               report_generator.py
               · 6 Chart.js visualizations
               · Networks table (SSID, encryption, RSSI)
               · Self-contained HTML — no server needed
                        │
                        ▼
                 report.html  📊
```

---

## 🏗️ System Architecture

```
              ┌──────────────────────────────────┐
              │          ESP32 Device            │
              │     (Embedded Firmware Layer)    │
              └───────────────┬──────────────────┘
                              │
     ┌────────────────────────┼────────────────────────┐
     │                        │                        │
┌────────────┐    ┌───────────────────┐    ┌───────────────────┐
│WiFi Scanner│    │  Packet Sniffer   │    │ Control Interface │
│(AP enum.)  │    │  (Monitor Mode)   │    │ (HTTP @ .4.1)     │
└─────┬──────┘    └────────┬──────────┘    └─────────┬─────────┘
      │                    │                         │
      └────────────────────┴─────────────────────────┘
                           │
           ┌───────────────┴─────────────────┐
           │                                 │
┌──────────────────────┐    ┌────────────────────────┐
│  Frame Processing    │    │   PCAP Writer          │
│  (802.11 parsing)    │    │   (ring buffer +       │
│  frame_analyzer.c    │    │    /api/pcap/download) │
└──────────────────────┘    └────────────────────────┘
                           │
              ┌────────────┴───────────────┐
              │     Host Python Analyzer   │
              │  pcap_analyzer.py          │
              │  frame_parser.py           │
              │  report_generator.py       │
              └────────────────────────────┘
```

### Processing Pipeline

1. **Sniffer** — promiscuous callback captures raw 802.11 frames on the AP channel
2. **PCAP Writer** — appends each frame to a 512 KB in-memory ring buffer with libpcap headers
3. **HTTP Interface** — browser at `192.168.4.1` downloads the buffer as a `.pcap` file
4. **Python Analyzer** — offline analysis: AP enumeration, client activity, channel statistics, visualisations

---

## 🛠️ Analyzer Suite

Three Python modules in `analyzer/`.

### `pcap_analyzer.py` — Main CLI

Full offline analysis of `.pcap`/`.pcapng` captures. AP table, client activity, channel distribution, CSV export, and Matplotlib plots.

### `frame_parser.py` — Per-frame Classification

Parses each frame into a `FrameInfo` dataclass. Extracted per frame:

| Field | Source | Notes |
|---|---|---|
| RSSI | Radiotap `DBM_SIGNAL` (bit 5) | Signed byte, dBm |
| Channel | Radiotap `CHANNEL` (bit 3) | Frequency (MHz) → channel lookup |
| Data Rate | Radiotap `RATE` (bit 2) | × 0.5 Mbps |
| SSID | Beacon IE tag 0 | UTF-8, `<hidden>` if empty |
| Encryption | RSN IE / vendor IE / cap flags | WPA2 / WPA / WEP / Open |
| Network Type | Capability ESS/IBSS bits | Infrastructure / Ad-Hoc |
| Src / Dst / BSSID | 802.11 MAC header | 6-byte fields at offsets 4/10/16 |

### `report_generator.py` — HTML Dashboard

Accepts JSON from `pcap_analyzer.py`. Produces a single self-contained `.html` file — no server, no dependencies, opens directly in any browser.

| Visualization | Type |
|---|---|
| Frames per Channel | Bar |
| Frame Categories | Doughnut |
| Frame Type Breakdown | Bar |
| RSSI Distribution | Bar (5 dBm buckets) |
| Data Rate Distribution | Bar |
| Top Transmitters | Bar |

---

## 📊 Technical Specifications

| Parameter | Value |
|---|---|
| **Target Hardware** | ESP32-WROOM-32 |
| **Firmware Framework** | ESP-IDF v5.1+ / FreeRTOS |
| **Capture Mode** | Promiscuous (monitor) mode |
| **PCAP Buffer** | 512 KB in-memory ring buffer |
| **HTTP Interface** | Soft-AP at `192.168.4.1` · 5 endpoints |
| **Supported Input Formats** | `.pcap`, `.pcapng` |
| **Python Dependencies** | Scapy, Pandas, Matplotlib (see `requirements.txt`) |
| **Minimum Python Version** | 3.10+ |
| **Report Format** | Self-contained HTML (Chart.js 4.x via CDN) |
| **Frequency Bands** | 2.4 GHz (CH 1–14) · 5 GHz (CH 36–165) |
| **ESP32 RX Sensitivity** | −97 dBm (datasheet) |

---

## 🔩 Hardware Requirements

| Component | Specification | Notes |
|---|---|---|
| Microcontroller | ESP32-WROOM-32 | WROOM-32D or WROOM-32U also compatible |
| USB Cable | Micro-USB, data-capable | Charge-only cables won't expose serial |
| Power Supply | 5V via USB or 3.3V external | External supply for standalone deployment |
| Flash Storage | 4 MB built-in | Sufficient for firmware + SPIFFS |
| Host Machine | Any OS with Python 3.10+ | For running the analyzer suite |

---

## 🚀 Build & Flash

Requires [ESP-IDF v5.1+](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/). See [`docs/setup_guide.md`](docs/setup_guide.md) for full environment setup.

```bash
cd firmware

# Source the ESP-IDF environment
. $IDF_PATH/export.sh

# Build
idf.py build

# Flash (adjust port)
idf.py -p /dev/ttyUSB0 flash

# Serial monitor
idf.py -p /dev/ttyUSB0 monitor
```

Expected serial output:

```
I (xxx) main: Soft-AP started  SSID='ESP32-ResearchLab'  CH=1
I (xxx) main: Web server running at http://192.168.4.1
I (xxx) main: Packet sniffer active – monitor mode enabled
```

---

## 🌐 HTTP Control Interface

Connect to Wi-Fi network **`ESP32-ResearchLab`** (password: `research1234`) and open `http://192.168.4.1`.

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | HTML dashboard |
| `/api/status` | GET | JSON: frame count, uptime |
| `/api/pcap/download` | GET | Download current capture as `.pcap` |
| `/api/pcap/reset` | POST | Clear the ring buffer |
| `/api/scan` | GET | Trigger an AP scan |

---

## 🐍 Python Analyzer

```bash
pip install -r requirements.txt

# Parse and summarise a capture
python analyzer/pcap_analyzer.py --file captures/capture.pcap

# Export AP and client tables to CSV
python analyzer/pcap_analyzer.py --file captures/capture.pcap --export csv

# Generate channel utilisation and encryption plots
python analyzer/pcap_analyzer.py --file captures/capture.pcap --plot

# Generate a full HTML report
python analyzer/report_generator.py --input results.json --output report.html
```

Reports and plots are saved to `reports/` (git-ignored).

---

## ✅ Features

- [x] Wi-Fi AP enumeration (SSID, BSSID, channel, encryption)
- [x] Passive packet capture in promiscuous/monitor mode
- [x] In-memory PCAP ring buffer with HTTP download
- [x] 802.11 frame classification (management / control / data)
- [x] Python offline analyzer: AP table, client activity, CSV export
- [x] Channel utilisation and encryption distribution plots (Matplotlib)
- [x] Self-contained HTML report with 6 Chart.js visualizations
- [x] Lightweight HTTP dashboard at `192.168.4.1`
- [ ] Python live dashboard (Streamlit) — *roadmap*
- [ ] Modular firmware refactor with sdkconfig presets — *roadmap*
- [ ] Vendor OUI lookup (MAC → manufacturer name) — *roadmap*
- [ ] Wireshark live-feed via USBPcap integration — *roadmap*

---

## 📁 Repository Structure

```
ESP32-WiFi-Security-Research-Lab/
│
├── firmware/                        # ESP-IDF C firmware
│   ├── CMakeLists.txt
│   └── main/
│       ├── main.c                   # Entry point: init + task loop
│       ├── wifi_manager.c/h         # Soft-AP + promiscuous sniffer
│       ├── web_server.c/h           # HTTP control interface (5 endpoints)
│       ├── pcap_writer.c/h          # In-memory PCAP ring buffer
│       └── CMakeLists.txt
│
├── analyzer/                        # Python offline analysis toolkit
│   ├── __init__.py
│   ├── pcap_analyzer.py             # CLI: parse + summarise + export
│   ├── frame_parser.py              # Per-frame classification (FrameInfo)
│   └── report_generator.py         # Self-contained HTML report generator
│
├── docs/
│   ├── setup_guide.md               # Flash, connect, analyse, troubleshoot
│   └── 80211_reference.md           # 802.11 frame structure reference
│
├── .github/
│   ├── workflows/lint.yml           # Python syntax check on every push
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
│
├── CHANGELOG.md                     # Version history and learning milestones
├── CONTRIBUTING.md                  # Contribution guidelines
├── requirements.txt                 # Python dependencies
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🗺️ Roadmap

| Status | Feature |
|---|---|
| ✅ Done | ESP32 firmware with promiscuous sniffer + PCAP ring buffer |
| ✅ Done | HTTP interface at `192.168.4.1` with 5 endpoints |
| ✅ Done | Python offline analyzer: AP table, client activity, CSV, plots |
| ✅ Done | Per-frame classifier with radiotap + beacon body parsing |
| ✅ Done | Self-contained HTML report with 6 Chart.js visualizations |
| 🔄 In progress | Modular firmware refactor with sdkconfig presets |
| 📋 Planned | Python live dashboard (Streamlit) |
| 📋 Planned | Vendor OUI lookup — MAC → manufacturer name |
| 📋 Planned | Wireshark live-feed via USBPcap integration |

---

## 📚 Documentation

| Document | Contents |
|---|---|
| [`docs/setup_guide.md`](docs/setup_guide.md) | Full environment setup, flash, connect, analyse, troubleshoot |
| [`docs/80211_reference.md`](docs/80211_reference.md) | 802.11 frame structure, IE table, deauth reason codes |
| Inline docstrings | Every C and Python function is documented |

---

## 🔗 Attribution

This project builds upon the foundational work of:

> **esp32-wifi-penetration-tool** by [@risinek](https://github.com/risinek)  
> https://github.com/risinek/esp32-wifi-penetration-tool

Full credit for the original firmware implementation belongs to the original author. This repository is an independent educational adaptation and is not affiliated with or endorsed by the original project.

---

## 🎓 Academic Context

This project is part of a personal learning path in **Telecommunications Engineering** at the **University of Granada**, covering:

- Wireless communication systems (IEEE 802.11)
- Embedded systems programming (ESP32 / ESP-IDF / FreeRTOS)
- Network packet structure and binary protocol analysis
- RF signal characterisation and passive monitoring techniques

It is intended to demonstrate practical, hands-on competency in low-level networking and embedded firmware development — not to be deployed in any production or adversarial context.

---

## 📜 License

Distributed under the **MIT License**, consistent with the upstream repository.  
See [`LICENSE`](LICENSE) for full terms.

---

<div align="center">

**⭐ Star this repository if it was useful for your studies!**

*Active learning project — feedback and pull requests are welcome.*
