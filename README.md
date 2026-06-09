# ESP32 Wireless Communications Research Lab

> A hands-on educational environment for studying IEEE 802.11 protocols, embedded firmware architecture, and wireless network behavior using ESP32 hardware.

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

This repository is a learning-focused adaptation of the open-source project [`esp32-wifi-penetration-tool`](https://github.com/risinek/esp32-wifi-penetration-tool) by [@risinek](https://github.com/risinek), used here exclusively as a reference for understanding WiFi protocol internals and embedded system design.

**Core study areas:**
- IEEE 802.11 frame structure and protocol behavior
- Passive packet capture and analysis in monitor mode
- ESP32 embedded firmware development (ESP-IDF)
- RF data collection workflows and analysis pipelines

---

## System Architecture

```
              ┌──────────────────────────────┐
              │         ESP32 Device         │
              │   (Embedded Firmware Layer)  │
              └─────────────┬────────────────┘
                            │
     ┌──────────────────────┼──────────────────────┐
     │                      │                      │
┌────────────┐    ┌──────────────────┐    ┌──────────────────┐
│WiFi Scanner│    │ Packet Sniffer   │    │Control Interface │
│(802.11 scan│    │ (Monitor Mode)   │    │ (Local Web UI)   │
└─────┬──────┘    └───────┬──────────┘    └────────┬─────────┘
      │                   │                        │
      └───────────────────┴────────────────────────┘
                          │
          ┌───────────────┴────────────────┐
          │                                │
┌─────────────────────┐    ┌───────────────────────┐
│  Frame Processing   │    │   Data Export Layer   │
│  (802.11 parsing)   │    │   (Logs / PCAP files) │
└─────────────────────┘    └───────────────────────┘
```

---

## Learning Objectives

This project was built to develop practical skills in:

- Wireless communication systems (WiFi / IEEE 802.11)
- Embedded C/C++ programming on constrained hardware
- Network packet structure analysis
- Passive RF monitoring and data capture techniques
- Firmware architecture design on ESP-IDF

---

## Hardware Requirements

| Component | Notes |
|---|---|
| ESP32-WROOM-32 (or equivalent) | Primary development board |
| USB cable | For flashing and serial monitoring |
| External power supply | Optional — for standalone deployment |

---

## Build & Flash

Built with the **ESP-IDF** framework.

```bash
idf.py build
idf.py flash
idf.py monitor
```

> Refer to the [ESP-IDF Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) for environment setup.

---

## Features Studied

- [x] WiFi network scanning and AP enumeration
- [x] Passive packet capture in monitor mode
- [x] 802.11 frame parsing and structure analysis
- [x] Controlled wireless environment experimentation
- [x] Local web-based control interface
- [ ] Python data visualization dashboard *(in progress)*
- [ ] Modular firmware refactor
- [ ] Wireshark integration for live analysis

---

## Roadmap

Planned improvements that remain strictly within academic scope:

- **Visualization layer** — Python dashboard for analyzing captured PCAP data offline
- **Simulation mode** — Non-intrusive environment for testing parsing logic without live RF
- **Improved logging** — Structured output with timestamps and frame metadata
- **Wireshark integration** — Streamlined export pipeline for `.pcapng` analysis

---

## Attribution

This project builds upon the foundational work of:

> **esp32-wifi-penetration-tool** by risinek  
> https://github.com/risinek/esp32-wifi-penetration-tool

Full credit for the original implementation belongs to the original author. This repository is an independent learning adaptation and is not affiliated with or endorsed by the original project.

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

This project is distributed under the **MIT License**, consistent with the license of the original upstream repository. See [`LICENSE`](./LICENSE) for full terms.
