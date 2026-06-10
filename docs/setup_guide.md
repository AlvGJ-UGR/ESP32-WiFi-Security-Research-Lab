# Setup Guide

## 1. Prerequisites

### Hardware

| Item | Notes |
|------|-------|
| ESP32-WROOM-32 (or DevKitC) | Any ESP32 with Wi-Fi |
| USB-A to Micro-USB cable | Data cable, not charge-only |
| Host PC (Linux / macOS / Windows) | For flashing and analysis |

### Software

| Tool | Version | Install |
|------|---------|---------|
| ESP-IDF | v5.1+ | [docs.espressif.com](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) |
| Python | 3.10+ | [python.org](https://www.python.org/) |
| Wireshark | 4.x (optional) | [wireshark.org](https://www.wireshark.org/) |

---

## 2. Flash the firmware

```bash
# 1. Clone the repo
git clone https://github.com/AlvGJ-UGR/ESP32-WiFi-Security-Research-Lab.git
cd ESP32-WiFi-Security-Research-Lab/firmware

# 2. Source ESP-IDF environment
. $IDF_PATH/export.sh        # Linux / macOS
# or: $IDF_PATH\export.bat   # Windows

# 3. Build
idf.py build

# 4. Flash  (adjust port as needed: /dev/ttyUSB0, COM3, …)
idf.py -p /dev/ttyUSB0 flash

# 5. Open serial monitor (115200 baud)
idf.py -p /dev/ttyUSB0 monitor
```

Expected output:
```
I (xxx) main: ESP32 Wi-Fi Research Lab – firmware starting
I (xxx) main: Soft-AP started  SSID='ESP32-ResearchLab'  CH=1
I (xxx) main: Web server running at http://192.168.4.1
I (xxx) main: Packet sniffer active – monitor mode enabled
```

---

## 3. Connect to the control interface

1. On your PC/phone, connect to Wi-Fi network **ESP32-ResearchLab** (password: `research1234`)
2. Open a browser and navigate to **http://192.168.4.1**
3. Use the dashboard to:
   - Check capture status (`/api/status`)
   - Download the current PCAP (`/api/pcap/download`)
   - Trigger an AP scan (`/api/scan`)
   - Reset the capture buffer (`POST /api/pcap/reset`)

---

## 4. Analyse captures with Python

```bash
# Install Python dependencies
pip install -r requirements.txt

# Analyse a downloaded PCAP
python analyzer/pcap_analyzer.py --file captures/capture.pcap

# Export to CSV
python analyzer/pcap_analyzer.py --file captures/capture.pcap --export csv

# Generate plots
python analyzer/pcap_analyzer.py --file captures/capture.pcap --plot
```

Reports and plots are saved to the `reports/` directory.

---

## 5. Open in Wireshark

```bash
wireshark captures/capture.pcap
```

Useful display filters for 802.11 analysis:

```
wlan.fc.type == 0          # Management frames only
wlan.fc.type_subtype == 8  # Beacon frames
wlan.fc.type_subtype == 4  # Probe Requests
wlan.addr == aa:bb:cc:dd:ee:ff  # Frames from specific MAC
```

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `idf.py: command not found` | IDF not sourced | Run `. $IDF_PATH/export.sh` |
| Serial monitor garbled | Wrong baud rate | Check 115200 baud |
| Can't connect to 192.168.4.1 | Not on ESP32 AP | Connect to `ESP32-ResearchLab` Wi-Fi first |
| PCAP download is empty | No frames captured yet | Wait ~30 s or move near a Wi-Fi network |
| Python `ModuleNotFoundError` | Missing dependencies | Run `pip install -r requirements.txt` |
