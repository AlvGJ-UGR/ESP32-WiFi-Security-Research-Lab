# ESP32 Wireless Communications Research Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.1%2B-red?logo=espressif)](https://docs.espressif.com/projects/esp-idf/en/latest/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Framework: ESP-IDF](https://img.shields.io/badge/Framework-ESP--IDF-orange)](https://idf.espressif.com/)
[![Status: Educational](https://img.shields.io/badge/Status-Educational-blue)](https://github.com/AlvGJ-UGR/ESP32-WiFi-Security-Research-Lab)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> A hands-on educational environment for studying IEEE 802.11 protocols, embedded firmware architecture, and wireless network behaviour using ESP32 hardware.

---

## ⚠️ Legal & Ethical Notice

This project is developed **strictly for educational and research purposes** within controlled environments.

All experimentation is conducted exclusively on:
- Hardware owned by the developer
- Networks under the developer's direct control
- Systems for which explicit written permission has been obtained

This repository does **not** endorse, support, or facilitate unauthorized access to networks, disruption of communications, or any activity prohibited by applicable law. Users are solely responsible for ensuring their use of this project complies with all local, national, and international regulations.

---

## Overview

This repository is a learning-focused adaptation of the open-source project [`esp32-wifi-penetration-tool`](https://github.com/risinek/esp32-wifi-penetration-tool) by [@risinek](https://github.com/risinek), used here exclusively as a reference for understanding Wi-Fi protocol internals and embedded system design.

**Core study areas:**
- IEEE 802.11 frame structure and protocol behaviour
- Passive packet capture and analysis in monitor mode
- ESP32 embedded firmware development (ESP-IDF)
- RF data collection workflows and offline analysis pipelines

---

## System Architecture

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
│(AP enum.)  │    │  (Monitor Mode)   │    │ (HTTP at .4.1)    │
└─────┬──────┘    └────────┬──────────┘    └─────────┬─────────┘
      │                    │                         │
      └────────────────────┴─────────────────────────┘
                           │
           ┌───────────────┴─────────────────┐
           │                                 │
┌──────────────────────┐    ┌────────────────────────┐
│  Frame Processing    │    │   PCAP Writer          │
│  (802.11 parsing)    │    │   (ring buffer + HTTP  │
│  frame_analyzer.c    │    │    /api/pcap/download) │
└──────────────────────┘    └────────────────────────┘
                           │
              ┌────────────┴───────────────┐
              │     Host Python Analyzer   │
              │  pcap_analyzer.py          │
              │  frame_parser.py           │
              │  visualizer.py             │
              └────────────────────────────┘
```

### Processing Pipeline

1. **Sniffer** — promiscuous callback captures raw 802.11 frames on the AP channel
2. **PCAP Writer** — appends each frame to a 512 KB in-memory ring buffer with libpcap headers
3. **HTTP Interface** — browser at `192.168.4.1` downloads the buffer as a `.pcap` file
4. **Python Analyzer** — offline analysis: AP enumeration, client activity, channel statistics, visualisations

---

## Repository Layout

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
│   └── visualizer.py               # Matplotlib plots
│
├── docs/
│   ├── setup_guide.md               # Flash, connect, analyse
│   └── 80211_reference.md           # 802.11 frame structure reference
│
├── .github/ISSUE_TEMPLATE/          # Bug report & feature request templates
├── requirements.txt                 # Python dependencies
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Learning Objectives

This project develops practical skills in:

- Wireless communication systems (Wi-Fi / IEEE 802.11)
- Embedded C/C++ programming on constrained hardware (FreeRTOS, ESP-IDF)
- Network packet structure analysis at the byte level
- Passive RF monitoring and PCAP data capture
- Python data analysis pipelines (Scapy, Pandas, Matplotlib)

---

## Hardware Requirements

| Component | Notes |
|-----------|-------|
| ESP32-WROOM-32 (or DevKitC) | Primary development board |
| USB data cable | Micro-USB, data-capable (not charge-only) |
| Host PC | Linux / macOS / Windows for flashing and analysis |
| External power (optional) | For standalone deployment |

---

## Build & Flash

Requires [ESP-IDF v5.1+](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/).

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

Expected output:
```
I (xxx) main: Soft-AP started  SSID='ESP32-ResearchLab'  CH=1
I (xxx) main: Web server running at http://192.168.4.1
I (xxx) main: Packet sniffer active – monitor mode enabled
```

See [`docs/setup_guide.md`](docs/setup_guide.md) for full environment setup and troubleshooting.

---

## HTTP Control Interface

Once the ESP32 is running, connect to Wi-Fi network **ESP32-ResearchLab** (password: `research1234`) and open `http://192.168.4.1`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | HTML dashboard |
| `/api/status` | GET | JSON: frame count, uptime |
| `/api/pcap/download` | GET | Download current capture as `.pcap` |
| `/api/pcap/reset` | POST | Clear the ring buffer |
| `/api/scan` | GET | Trigger an AP scan |

---

## Python Analyzer

```bash
pip install -r requirements.txt

# Parse and summarise a capture
python analyzer/pcap_analyzer.py --file captures/capture.pcap

# Export AP and client tables to CSV
python analyzer/pcap_analyzer.py --file captures/capture.pcap --export csv

# Generate channel utilisation and encryption plots
python analyzer/pcap_analyzer.py --file captures/capture.pcap --plot
```

Reports and plots are saved to `reports/` (git-ignored).

---

## Features

- [x] Wi-Fi AP enumeration (SSID, BSSID, channel, encryption)
- [x] Passive packet capture in monitor mode
- [x] In-memory PCAP ring buffer with HTTP download
- [x] 802.11 frame classification (management / control / data)
- [x] Python offline analyzer: AP table, client activity, CSV export
- [x] Channel utilisation and encryption distribution plots
- [x] Lightweight HTTP dashboard at 192.168.4.1
- [ ] Python live dashboard (Streamlit) — *roadmap*
- [ ] Modular firmware refactor with sdkconfig presets — *roadmap*
- [ ] Wireshark live-feed via USBPcap integration — *roadmap*

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/setup_guide.md`](docs/setup_guide.md) | Full environment setup, flash, connect, analyse, troubleshoot |
| [`docs/80211_reference.md`](docs/80211_reference.md) | 802.11 frame structure, IE table, deauth reason codes, Scapy snippets |
| Inline docstrings | Every C and Python function is documented |

---

## Attribution

This project builds upon the foundational work of:

> **esp32-wifi-penetration-tool** by risinek  
> https://github.com/risinek/esp32-wifi-penetration-tool

Full credit for the original implementation belongs to the original author. This repository is an independent educational adaptation and is not affiliated with or endorsed by the original project.

---

## Context

This work is part of a personal learning path in:
- Telecommunications Engineering
- Embedded Systems Development
- Wireless Communication Protocols
- Computer Networks & Security Fundamentals

It is intended to demonstrate hands-on competency in low-level networking, embedded firmware development, and practical protocol analysis — not to be deployed in any production or adversarial context.

---

## License

Distributed under the **MIT License**, consistent with the license of the upstream repository.  
See [`LICENSE`](LICENSE) for full terms.

---

**Star ⭐ this repository if it was useful for your studies!**

*Active learning project — feedback and pull requests are welcome.*
