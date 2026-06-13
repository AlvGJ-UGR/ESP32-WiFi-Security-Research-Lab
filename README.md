<div align="center">

# 📡 ESP32 WiFi Security Research Lab

**Passive IEEE 802.11 analysis platform — from ESP32 monitor-mode firmware to interactive dashboards**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.1+-E7352C?style=flat-square&logo=espressif&logoColor=white)](https://docs.espressif.com/projects/esp-idf/en/latest/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![Scope](https://img.shields.io/badge/Scope-Educational%20%2F%20Research-blue?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![University](https://img.shields.io/badge/UGR-Telecomunicaciones-red?style=flat-square)]()

<br/>

*Full-stack 802.11 analysis — from ESP32 firmware with HTTP interface*  
*to interactive TUI menu, Streamlit live dashboard, OUI vendor lookup, and Wireshark live-feed.*

</div>

---

> ⚠️ **Legal & Ethical Notice** — This project is developed strictly for educational and research purposes within controlled environments. All experimentation is conducted exclusively on hardware owned by the developer, networks under the developer's direct control, or systems for which explicit written permission has been obtained. This repository does **not** endorse, support, or facilitate unauthorized access to networks, disruption of communications, or any activity prohibited by applicable law. Users are solely responsible for ensuring compliance with all applicable regulations.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Pipeline](#-pipeline)
- [System Architecture](#-system-architecture)
- [Quick Start](#-quick-start)
- [Interactive TUI Menu](#-interactive-tui-menu)
- [Analyzer Suite](#-analyzer-suite)
- [Technical Specifications](#-technical-specifications)
- [Hardware Requirements](#-hardware-requirements)
- [Build & Flash](#-build--flash)
- [HTTP Control Interface](#-http-control-interface)
- [Python Analyzer](#-python-analyzer)
- [Live Dashboard](#-live-dashboard)
- [Wireshark Integration](#-wireshark-integration)
- [OUI Vendor Lookup](#-oui-vendor-lookup)
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

- **Firmware layer** — ESP32 in promiscuous mode captures raw 802.11 frames, writes them to a 512 KB in-memory PCAP ring buffer, and serves them via HTTP
- **Binary parsing layer** — Zero-dependency parsers for `.pcap` and `.pcapng` with full radiotap and beacon body extraction
- **Analysis layer** — Frame classification, channel stats, AP enumeration, client activity, CSV/JSON export, WPA3 detection
- **Visualization layer** — 4 Matplotlib plots + combined dashboard + Streamlit live dashboard + self-contained HTML reports + direct Wireshark live-feed
- **Interface layer** — Interactive TUI menu (`menu.py`) for point-and-click terminal usage with no arguments required

| Area | Topics Covered |
|---|---|
| 802.11 Protocol | Frame types/subtypes, beacon body, IEs, capability flags, WPA3 SAE detection |
| RF Analysis | RSSI, channel mapping, frequency lookup, data rate distribution, 2.4/5/6 GHz bands |
| Embedded Systems | ESP-IDF, FreeRTOS, promiscuous mode API, `wifi_promiscuous_pkt_t` |
| Networking | HTTP server on ESP32, PCAP ring buffer, Soft-AP |
| Binary Formats | PCAP/PCAPNG structure, radiotap bitmap walking, IE parsing |
| Vendor Intelligence | IEEE OUI registry, MAC → manufacturer resolution |

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
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
pcap_analyzer.py  pcap_parser.py  wireshark_export.py
· AP/client table · Radiotap       · Pipe / stdout /
· WPA3 detection    parsing          file modes
· CSV + JSON      · SSID/encrypt  · Live Wireshark feed
· 4 MPL plots     · Avg RSSI
· Dashboard PNG   
        │               │
        └───────┬────────┘
                │
         frames.json
                │
         ┌──────┴──────────┐
         │                 │
         ▼                 ▼
  dashboard.py      report_generator.py
  Streamlit live    Self-contained HTML
  6 Plotly charts   6 Chart.js charts
  Auto-refresh      Zero dependencies
  OUI table         Encryption colours
                        │
                        ▼
                    menu.py
              Interactive TUI menu
              (analyze · export · plot
               pipeline · deps check)
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
│  frame_parser.py     │    │    /api/pcap/download) │
└──────────────────────┘    └────────────────────────┘
                           │
       ┌───────────────────┼──────────────────────┐
       │                   │                      │
       ▼                   ▼                      ▼
pcap_analyzer.py    dashboard.py       wireshark_export.py
visualizer.py       (Streamlit)        (pipe/stdout/file)
oui_lookup.py
report_generator.py
       │
       ▼
   menu.py  ◄── Interactive TUI (entry point for end users)
```

---

## 🚀 Quick Start

```bash
# 1. Clone and install dependencies
git clone https://github.com/AlvGJ-UGR/ESP32-WiFi-Security-Research-Lab.git
cd ESP32-WiFi-Security-Research-Lab
pip install -r requirements.txt

# 2. Launch the interactive menu (recommended)
python menu.py

# 3. Or use the CLI directly
python analyzer/pcap_analyzer.py --file captures/sample.pcap
```

The interactive menu is the easiest entry point — no arguments needed, it guides you through every step.

---

## 🖥️ Interactive TUI Menu

`menu.py` is the main entry point for day-to-day use. Launch it with:

```bash
python menu.py
```

```
  ███████╗███████╗██████╗ ██████╗ ██████╗
  ██╔════╝██╔════╝██╔══██╗╚════██╗╚════██╗
  █████╗  ███████╗██████╔╝ █████╔╝ █████╔╝
  ██╔══╝  ╚════██║██╔═══╝ ██╔═══╝  ╚═══██╗
  ███████╗███████║██║      ███████╗██████╔╝
  ╚══════╝╚══════╝╚═╝      ╚══════╝╚═════╝

  WiFi Security Research Lab  ·  ESP32 Edition
  ─────────────────────────────────────────────

  1   Analizar captura        Parsea un PCAP y muestra el resumen
  2   Analizar directorio     Procesa todos los PCAPs de una carpeta
  3   Exportar resultados     Exporta a CSV y/o JSON
  4   Generar gráficas        Canal, cifrado, clientes, timeline…
  5   Pipeline completo       Analizar + exportar + graficar en un paso
  6   Ver reportes            Lista los archivos generados en /reports

  7   Comprobar dependencias  Verifica si todos los paquetes están instalados
  8   Instalar dependencias   Ejecuta pip install automáticamente
  9   Acerca del proyecto     Información y créditos
  q   Salir
```

### Menu features

| Option | What it does |
|---|---|
| **1 – Analizar captura** | Interactive file picker from `captures/`, shows AP table + client table + channel stats |
| **2 – Analizar directorio** | Batch-processes every `.pcap`/`.pcapng` in a folder |
| **3 – Exportar resultados** | Choose CSV, JSON, or both; configurable output directory |
| **4 – Generar gráficas** | Pick individual plots or generate all four + the dashboard PNG |
| **5 – Pipeline completo** | One-shot: parse → summary → CSV + JSON → all plots, no extra prompts |
| **6 – Ver reportes** | Table of generated files with size and timestamp; offers to open the folder |
| **7 – Comprobar dependencias** | Status table (✔ / ✘) for every required package |
| **8 – Instalar dependencias** | Runs `pip install -r requirements.txt` without leaving the menu |

The file picker shows name, size, and modification date for every capture found in `captures/`. You can also type a custom path at any prompt.

---

## 🛠️ Analyzer Suite

Six Python modules in `analyzer/`. The core parsers (`pcap_parser`, `frame_parser`, `oui_lookup`, `report_generator`, `wireshark_export`) use only the standard library. Optional deps listed in `requirements.txt`.

### `pcap_analyzer.py` — Main CLI

Full offline analysis of `.pcap`/`.pcapng`. Typed dataclasses (`AccessPoint`, `Client`, `AnalysisResult`), AP table, client activity, channel distribution, CSV + JSON export, WPA3 detection, batch directory mode.

```bash
# Single file
python analyzer/pcap_analyzer.py --file captures/capture.pcap

# Export to CSV and JSON at once
python analyzer/pcap_analyzer.py --file captures/capture.pcap --export csv json

# Generate all plots
python analyzer/pcap_analyzer.py --file captures/capture.pcap --plot

# Batch-process a directory
python analyzer/pcap_analyzer.py --dir captures/ --export csv

# Custom output directory
python analyzer/pcap_analyzer.py --file captures/capture.pcap --export json --out-dir results/
```

**Key improvements over v1:**

| Area | What changed |
|---|---|
| Data model | Typed `@dataclass` for AP, Client and AnalysisResult — no more raw dicts |
| Encryption | WPA3 detection via AKM Suite `00:0F:AC:08` (SAE) in the RSN IE |
| Export | Added JSON export alongside CSV |
| Batch mode | `--dir` flag processes every PCAP in a folder |
| Performance | Single `_iter_elts()` generator replaces three separate `getlayer()` traversals |
| Logging | `logging` module throughout — use `--verbose` for debug output |

### `visualizer.py` — Matplotlib Plots

Four individual plots plus a combined 2×2 dashboard. Accepts both the new dataclasses and the legacy dict format.

| Function | Output |
|---|---|
| `plot_channel_utilization()` | Bar chart split by 2.4 / 5 / 6 GHz band |
| `plot_encryption_distribution()` | Donut chart with centre label showing AP count |
| `plot_client_activity()` | Horizontal bars, top-N clients by frame count |
| `plot_beacon_timeline()` | Stacked area chart, beacon density over capture time |
| `plot_dashboard()` | All four plots in a single 2×2 figure |
| `plot_all()` | Generates every plot and the dashboard in one call |

```python
from analyzer.visualizer import plot_all
plot_all(result, out_dir="reports")          # individual PNGs + dashboard
plot_all(result, individual=False)           # dashboard only
```

### `frame_parser.py` — Per-frame Classifier

Parses each frame into a `FrameInfo` dataclass. Extracted fields:

| Field | Source | Notes |
|---|---|---|
| RSSI | Radiotap `DBM_SIGNAL` | Signed byte, dBm |
| Channel | Radiotap `CHANNEL` | MHz → channel lookup |
| Data Rate | Radiotap `RATE` | × 0.5 Mbps |
| SSID | Beacon IE tag 0 | `<hidden>` if empty |
| Encryption | RSN IE / vendor IE / cap flags | WPA3 / WPA2 / WPA / WEP / Open |
| Network Type | Capability ESS/IBSS bits | Infrastructure / Ad-Hoc |
| Src / Dst / BSSID | 802.11 MAC header | Offsets 4/10/16 |

### `oui_lookup.py` — Vendor Resolution

Resolves MAC address prefixes to manufacturer names.

```bash
python analyzer/oui_lookup.py AA:BB:CC:DD:EE:FF
python analyzer/oui_lookup.py --update-db          # download full IEEE registry
python analyzer/oui_lookup.py --stats frames.json  # vendor breakdown
```

### `report_generator.py` — HTML Dashboard

Self-contained `.html` report from any JSON output. No server, no dependencies.

| Visualization | Chart Type |
|---|---|
| Frames per Channel | Bar |
| Frame Categories | Doughnut |
| Frame Type Breakdown | Bar |
| RSSI Distribution | Histogram (5 dBm buckets) |
| Data Rate Distribution | Bar |
| Top Transmitters | Bar |

### `dashboard.py` — Streamlit Live Dashboard

Interactive live dashboard with auto-refresh. See [Live Dashboard](#-live-dashboard).

### `wireshark_export.py` — Wireshark Live-Feed

Streams captures directly into Wireshark. See [Wireshark Integration](#-wireshark-integration).

---

## 📊 Technical Specifications

| Parameter | Value |
|---|---|
| **Target Hardware** | ESP32-WROOM-32 |
| **Firmware Framework** | ESP-IDF v5.1+ / FreeRTOS |
| **Capture Mode** | Promiscuous (monitor) mode |
| **PCAP Buffer** | 512 KB in-memory ring buffer |
| **HTTP Interface** | Soft-AP at `192.168.4.1` · 5 endpoints |
| **Supported Formats** | `.pcap`, `.pcapng`, `.cap` |
| **Core Dependencies** | None — Python stdlib only |
| **Optional Deps** | Streamlit · Plotly · Pandas · Matplotlib · Scapy · Rich |
| **Minimum Python** | 3.10+ |
| **Report Formats** | Interactive TUI · Streamlit dashboard · self-contained HTML · CSV · JSON |
| **Plots** | 4 individual Matplotlib PNGs + combined 2×2 dashboard |
| **OUI Entries (built-in)** | ~120 common manufacturers |
| **OUI Entries (full DB)** | ~35,000 (IEEE registry, optional download) |
| **Frequency Bands** | 2.4 GHz (CH 1–14) · 5 GHz (CH 36–177) · 6 GHz (CH 177+) |
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
. $IDF_PATH/export.sh
idf.py build
idf.py -p /dev/ttyUSB0 flash
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

Connect to **`ESP32-ResearchLab`** (password: `research1234`) and open `http://192.168.4.1`.

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | HTML dashboard |
| `/api/status` | GET | JSON: frame count, uptime |
| `/api/pcap/download` | GET | Download capture as `.pcap` |
| `/api/pcap/reset` | POST | Clear the ring buffer |
| `/api/scan` | GET | Trigger AP scan |

---

## 🐍 Python Analyzer

```bash
pip install -r requirements.txt

# Recommended: interactive menu
python menu.py

# Or use the CLI directly
python analyzer/pcap_analyzer.py --file captures/capture.pcap
python analyzer/pcap_analyzer.py --file captures/capture.pcap --export csv json
python analyzer/pcap_analyzer.py --file captures/capture.pcap --plot
python analyzer/pcap_analyzer.py --dir captures/ --export csv

# Enriched JSON from the binary parser:
python analyzer/pcap_parser.py --file capture.pcapng --export frames.json
python analyzer/report_generator.py --input frames.json --output report.html
```

---

## 📊 Live Dashboard

Interactive Streamlit dashboard with 6 Plotly charts, networks table, and RSSI timeline.

```bash
pip install streamlit plotly pandas

# Load a local frames.json
streamlit run analyzer/dashboard.py

# Or point directly at the ESP32 (live mode with auto-refresh)
streamlit run analyzer/dashboard.py -- --live http://192.168.4.1/api/pcap/download
```

The dashboard auto-detects input format and enriches vendor names via `oui_lookup.py`.

---

## 🦈 Wireshark Integration

Stream captures from the ESP32 directly into Wireshark for real-time analysis.

```bash
# Named pipe — Wireshark opens automatically (Linux/macOS)
python analyzer/wireshark_export.py --mode pipe --url http://192.168.4.1/api/pcap/download

# Pipe to Wireshark via stdout (all platforms)
python analyzer/wireshark_export.py --mode stdout --url http://192.168.4.1/api/pcap/download \
  | wireshark -k -i -

# File polling — saves timestamped .pcap files and opens each in Wireshark
python analyzer/wireshark_export.py --mode file --url http://192.168.4.1/api/pcap/download --interval 10

# Open an existing capture in Wireshark
python analyzer/wireshark_export.py --open captures/capture_20241115_143022.pcap
```

---

## 🔍 OUI Vendor Lookup

Resolve MAC addresses to manufacturer names using the built-in curated table or the full IEEE registry.

```bash
# Resolve a single MAC
python analyzer/oui_lookup.py AA:BB:CC:DD:EE:FF
#   MAC    : AA:BB:CC:DD:EE:FF
#   OUI    : AA:BB:CC
#   Vendor : Apple, Inc.
#   Source : built-in

# Download the full IEEE OUI registry (~35,000 entries, ~5 MB, one-time)
python analyzer/oui_lookup.py --update-db

# Top vendors in a capture
python analyzer/oui_lookup.py --stats frames.json --top 15
```

Built-in table covers ~120 most common manufacturers: Apple, Samsung, Intel, TP-Link, Netgear, Huawei, Xiaomi, Google, Amazon, Ubiquiti, ASUS, Espressif, Raspberry Pi, and more.

---

## ✅ Features

- [x] Wi-Fi AP enumeration (SSID, BSSID, channel, encryption, WPA3 detection)
- [x] Passive packet capture in promiscuous/monitor mode
- [x] In-memory PCAP ring buffer with HTTP download
- [x] 802.11 frame classification (management / control / data)
- [x] **Interactive TUI menu** — no arguments needed, file picker, pipeline in one step
- [x] Python offline analyzer: typed dataclasses, AP table, client activity
- [x] CSV and JSON export (both in one command)
- [x] Batch directory processing (`--dir`)
- [x] Channel utilisation, encryption distribution, client activity, and beacon timeline plots
- [x] Combined 2×2 dashboard PNG (all plots in one figure)
- [x] Self-contained HTML report with 6 Chart.js visualizations
- [x] MAC → vendor resolution (built-in table + optional full IEEE registry)
- [x] Streamlit live dashboard with 6 Plotly charts and auto-refresh
- [x] Wireshark live-feed (pipe / stdout / file polling modes)
- [x] Lightweight HTTP dashboard at `192.168.4.1`
- [x] Dependency checker and auto-installer from the menu
- [ ] Modular firmware refactor with sdkconfig presets — *in progress*
- [ ] Jupyter notebook for interactive PCAP exploration — *planned*

---

## 📁 Repository Structure

```
ESP32-WiFi-Security-Research-Lab/
│
├── menu.py                           # ★ Interactive TUI — start here
│
├── analyzer/                         # Python analysis suite
│   ├── pcap_analyzer.py              # Main CLI: parse + summarise + export (CSV/JSON)
│   ├── visualizer.py                 # Matplotlib: 4 plots + 2×2 dashboard
│   ├── frame_parser.py               # Per-frame classification (FrameInfo dataclass)
│   ├── pcap_parser.py                # Binary PCAP/PCAPNG parser + radiotap
│   ├── oui_lookup.py                 # MAC → vendor resolution (OUI)
│   ├── dashboard.py                  # Streamlit live dashboard (Plotly)
│   ├── wireshark_export.py           # Wireshark live-feed (pipe/stdout/file)
│   └── report_generator.py          # Self-contained HTML report generator
│
├── captures/                         # Drop your .pcap / .pcapng files here
│
├── reports/                          # Generated CSV, JSON, and PNG outputs
│
├── docs/
│   ├── setup_guide.md                # Flash, connect, analyse, troubleshoot
│   └── 80211_reference.md            # 802.11 frame structure reference
│
├── .github/
│   ├── workflows/lint.yml            # Python syntax check on every push
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
│
├── CHANGELOG.md
├── CONTRIBUTING.md
├── requirements.txt
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
| ✅ Done | Python offline analyzer: typed dataclasses, AP table, client activity |
| ✅ Done | CSV and JSON export; batch directory mode |
| ✅ Done | WPA3 detection via RSN AKM Suite (SAE) |
| ✅ Done | 4 Matplotlib plots + combined 2×2 dashboard PNG |
| ✅ Done | Binary PCAP/PCAPNG parser with radiotap + beacon body extraction |
| ✅ Done | Self-contained HTML report with 6 Chart.js visualizations |
| ✅ Done | MAC → vendor lookup (built-in table + full IEEE OUI registry) |
| ✅ Done | Streamlit live dashboard with Plotly charts and auto-refresh |
| ✅ Done | Wireshark live-feed (pipe / stdout / file modes) |
| ✅ Done | **Interactive TUI menu** with file picker, pipeline, and dependency manager |
| 🔄 In progress | Modular firmware refactor with sdkconfig presets |
| 📋 Planned | Jupyter notebook for interactive PCAP exploration |

---

## 📚 Documentation

| Document | Contents |
|---|---|
| [`docs/setup_guide.md`](docs/setup_guide.md) | Full ESP-IDF setup, flash, connect, troubleshoot |
| [`docs/80211_reference.md`](docs/80211_reference.md) | 802.11 frame structure, IE table, deauth reason codes |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history and learning milestones |
| Inline docstrings | Every Python module and function documented |

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

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full terms.

---

<div align="center">

**⭐ Star this repository if it was useful for your studies!**

*Active learning project — feedback and pull requests are welcome.*

</div>
