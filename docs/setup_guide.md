# ESP-IDF Environment Setup Guide

Step-by-step guide to set up the ESP-IDF development environment and get the firmware running on an ESP32-WROOM-32.

---

## Prerequisites

- ESP32-WROOM-32 development board (or equivalent with WROOM-32 module)
- USB-A to Micro-USB cable (data-capable, not charge-only)
- Linux, macOS, or Windows 10/11
- ~3 GB free disk space for the toolchain

---

## 1. Install ESP-IDF

### Linux / macOS

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install git wget flex bison gperf python3 python3-pip \
    python3-venv cmake ninja-build ccache libffi-dev libssl-dev \
    dfu-util libusb-1.0-0

# Clone ESP-IDF (v5.x recommended)
mkdir -p ~/esp
cd ~/esp
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf

# Run the install script
./install.sh esp32

# Set up environment variables (add to ~/.bashrc to persist)
. ./export.sh
```

### Windows

Download and run the [ESP-IDF Windows Installer](https://dl.espressif.com/dl/esp-idf/) — it handles the toolchain, Python, and Git automatically.

---

## 2. Verify Installation

```bash
idf.py --version
# Expected output: ESP-IDF v5.x.x
```

---

## 3. Clone and Build the Firmware

```bash
# Clone the upstream project (this repo is a study adaptation of it)
git clone https://github.com/risinek/esp32-wifi-penetration-tool.git
cd esp32-wifi-penetration-tool

# Set the target chip
idf.py set-target esp32

# Build
idf.py build
```

Build time is typically 2–5 minutes on first run (compiles the full ESP-IDF + project).

---

## 4. Flash to the ESP32

```bash
# Replace /dev/ttyUSB0 with your actual port
# Linux: usually /dev/ttyUSB0 or /dev/ttyACM0
# macOS: /dev/cu.usbserial-XXXX
# Windows: COMX

idf.py -p /dev/ttyUSB0 flash
```

**If flashing fails:**
- Hold the BOOT button on the ESP32 board while the flash command starts
- Check that the cable is data-capable (charge-only cables don't expose the serial interface)
- On Linux, add your user to the `dialout` group: `sudo usermod -aG dialout $USER` then log out and back in

---

## 5. Open the Serial Monitor

```bash
idf.py -p /dev/ttyUSB0 monitor
```

Exit with `Ctrl+]`.

To **save the output to a file** for analysis with `wifi_analyzer.py`:

```bash
idf.py -p /dev/ttyUSB0 monitor | tee monitor.log
```

---

## 6. Finding Your Serial Port

### Linux
```bash
ls /dev/tty* | grep -E 'USB|ACM'
# or
dmesg | grep tty
```

### macOS
```bash
ls /dev/cu.*
```

### Windows

Open Device Manager → Ports (COM & LPT) → look for "Silicon Labs CP210x" or "CH340".

---

## 7. Combining Build + Flash + Monitor

```bash
idf.py -p /dev/ttyUSB0 build flash monitor
```

---

## 8. Running the Python Analyzer

Once you have a `monitor.log` or a `.pcap`/`.pcapng` file from the ESP32:

```bash
cd analyzer/

# From serial log:
python3 wifi_analyzer.py --log ../monitor.log --export results.json
python3 report_generator.py --input results.json --output report.html

# From PCAP/PCAPNG:
python3 pcap_parser.py --file capture.pcapng --export frames.json
python3 report_generator.py --input frames.json --output report.html
```

Open `report.html` in any browser — no server required.

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| `Permission denied: /dev/ttyUSB0` | User not in dialout group | `sudo usermod -aG dialout $USER` |
| `Failed to connect to ESP32` | Boot mode issue | Hold BOOT button during flash |
| `idf.py: command not found` | export.sh not sourced | Run `. ~/esp/esp-idf/export.sh` |
| Build fails with Python error | Wrong Python version | ESP-IDF requires Python 3.8+ |
| Monitor shows garbage characters | Wrong baud rate | Default is 115200, set with `-b 115200` |

---

## Notes on Monitor Mode and Promiscuous Capture

The ESP32 enters monitor (promiscuous) mode via `esp_wifi_set_promiscuous(true)` in the firmware. In this mode:

- The radio receives **all 802.11 frames** on the configured channel, not just those addressed to the device
- Each frame arrives via a callback with a `wifi_promiscuous_pkt_t` struct that includes:
  - `rx_ctrl.rssi` — received signal strength in dBm
  - `rx_ctrl.channel` — channel the frame was received on
  - `payload[]` — raw 802.11 frame bytes
- The ESP32 cannot receive on multiple channels simultaneously — channel hopping requires changing the channel in a loop (`esp_wifi_set_channel()`)

This is fundamentally a **passive, receive-only** mode. The radio does not transmit during promiscuous capture.
