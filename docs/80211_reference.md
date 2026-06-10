# IEEE 802.11 Frame Reference

Quick-reference for the frame types encountered in captures from this lab.

---

## Frame Type Hierarchy

```
802.11 Frame
├── Type 0 – Management
│   ├── Subtype 0  – Association Request
│   ├── Subtype 1  – Association Response
│   ├── Subtype 4  – Probe Request
│   ├── Subtype 5  – Probe Response
│   ├── Subtype 8  – Beacon
│   ├── Subtype 10 – Disassociation
│   ├── Subtype 11 – Authentication
│   └── Subtype 12 – Deauthentication
├── Type 1 – Control
│   ├── Subtype 11 – RTS
│   ├── Subtype 12 – CTS
│   └── Subtype 13 – ACK
└── Type 2 – Data
    ├── Subtype 0  – Data
    ├── Subtype 4  – Null (power save)
    └── Subtype 8  – QoS Data
```

---

## General Frame Structure

```
 Bytes:  2        2      6      6      6     2      6       variable    4
       ┌──────┬───────┬──────┬──────┬──────┬────┬──────┬────────────┬─────┐
       │Frame │Duration│Addr1 │Addr2 │Addr3 │Seq │Addr4 │Frame Body  │ FCS │
       │Control│       │(DA)  │(SA)  │(BSSID)│Ctrl│(opt) │(payload)   │     │
       └──────┴───────┴──────┴──────┴──────┴────┴──────┴────────────┴─────┘
```

**Frame Control field (2 bytes):**

```
Bits:  0-1    2-3     4-7       8      9      10     11    12    13    14   15
      ┌─────┬──────┬─────────┬──────┬──────┬──────┬────┬─────┬────┬─────┬────┐
      │Proto│ Type │ Subtype │ToDS  │FromDS│MoreF │Rtry│PwrM │MDF │Prot │Ord │
      └─────┴──────┴─────────┴──────┴──────┴──────┴────┴─────┴────┴─────┴────┘
```

---

## Beacon Frame Body

Beacons are broadcast every ~100 ms by the AP and contain:

| Field | Size | Description |
|-------|------|-------------|
| Timestamp | 8 B | Microseconds since AP boot |
| Beacon Interval | 2 B | Usually 100 TU (≈ 102.4 ms) |
| Capability Info | 2 B | ESS, Privacy, Short Preamble… |
| SSID (IE 0) | variable | Network name (0 = hidden) |
| Supported Rates (IE 1) | variable | 1–54 Mbps legacy rates |
| DS Parameter Set (IE 3) | 3 B | Current channel |
| RSN (IE 48) | variable | WPA2 cipher/auth suites |

---

## Information Elements (IEs)

| ID | Name | Key info |
|----|------|----------|
| 0  | SSID | Network name |
| 1  | Supported Rates | Legacy rates |
| 3  | DS Parameter Set | Channel number |
| 7  | Country | Regulatory domain |
| 48 | RSN | WPA2 parameters |
| 50 | Extended Supported Rates | HT/VHT rates |
| 221 | Vendor Specific | WPA (OUI 00:50:F2:01), WPS, etc. |

---

## Deauthentication Reason Codes

| Code | Meaning |
|------|---------|
| 1 | Unspecified reason |
| 2 | Previous auth no longer valid |
| 3 | Deauthenticated because leaving BSS |
| 4 | Inactivity / AP is leaving |
| 6 | Class 2 frame from non-auth STA |
| 7 | Class 3 frame from non-assoc STA |

---

## Encryption Detection (via IEs)

```
IE 48 present (RSN)          → WPA2 / WPA3
IE 221 with OUI 00:50:F2:01  → WPA (legacy)
Neither present              → Open or WEP (check Capability Privacy bit)
```

---

## Scapy Quick Reference

```python
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt

pkts = rdpcap("capture.pcap")

# Filter beacons
beacons = [p for p in pkts if p.haslayer(Dot11Beacon)]

# Extract SSID
ssid = beacons[0].getlayer(Dot11Elt).info.decode()

# Extract channel
elt = beacons[0].getlayer(Dot11Elt)
while elt:
    if elt.ID == 3:
        print("Channel:", elt.info[0])
    elt = elt.payload.getlayer(Dot11Elt)
```
