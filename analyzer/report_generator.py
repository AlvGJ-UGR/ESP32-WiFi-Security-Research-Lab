"""
report_generator.py
-------------------
Generates a self-contained HTML report from the JSON output produced
by wifi_analyzer.py or pcap_parser.py.

Usage:
    # From wifi_analyzer output:
    python wifi_analyzer.py --log monitor.log --export results.json
    python report_generator.py --input results.json --output report.html

    # From pcap_parser output:
    python pcap_parser.py --file capture.pcap --export frames.json
    python report_generator.py --input frames.json --mode pcap --output report.html
"""

import json
import argparse
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path


# -----------------------------------------------------------------
# Data Processing
# -----------------------------------------------------------------

def process_analyzer_data(data: dict) -> dict:
    """Process output from wifi_analyzer.py into report-ready structures."""
    stats    = data.get("stats", {})
    networks = data.get("networks", {})
    frames   = data.get("frames", [])

    # Channel distribution
    channels = {str(k): v for k, v in stats.get("frames_by_channel", {}).items()}

    # Category distribution
    categories = stats.get("frames_by_category", {})

    # Frame type breakdown
    type_counter = defaultdict(int)
    for f in frames:
        type_counter[f.get("type_name", "Unknown")] += 1
    frame_types = dict(sorted(type_counter.items(), key=lambda x: -x[1])[:12])

    # RSSI histogram (buckets of 5 dBm)
    rssi_buckets = defaultdict(int)
    for f in frames:
        rssi = f.get("rssi")
        if rssi is not None:
            bucket = (rssi // 5) * 5
            rssi_buckets[bucket] += 1
    rssi_hist = dict(sorted(rssi_buckets.items()))

    # Top talkers
    top_talkers = dict(stats.get("top_talkers", [])[:8])

    # Networks table
    net_rows = []
    for ssid, meta in networks.items():
        net_rows.append({
            "ssid":      ssid,
            "bssid":     meta.get("bssid", "—"),
            "channel":   meta.get("channel", "—"),
            "rssi_min":  meta.get("rssi_min", "—"),
            "rssi_max":  meta.get("rssi_max", "—"),
            "beacons":   meta.get("beacons", "—"),
        })
    net_rows.sort(key=lambda x: x["beacons"], reverse=True)

    return {
        "mode":        "analyzer",
        "total_frames": stats.get("total_frames", 0),
        "total_networks": stats.get("total_networks", 0),
        "avg_rssi":    stats.get("avg_rssi"),
        "min_rssi":    stats.get("min_rssi"),
        "max_rssi":    stats.get("max_rssi"),
        "parsed_at":   stats.get("parsed_at", "—"),
        "channels":    channels,
        "categories":  categories,
        "frame_types": frame_types,
        "rssi_hist":   rssi_hist,
        "top_talkers": top_talkers,
        "networks":    net_rows,
    }


def process_pcap_data(data) -> dict:
    """
    Process output from pcap_parser.py into report-ready structures.

    Accepts two formats:
      - New enriched format: dict with 'summary' + 'frames' keys
        (produced by: python pcap_parser.py --export frames.json)
      - Legacy format: plain list of frame dicts (backwards compatible)
    """
    # ── New enriched format ──────────────────────────────────────
    if isinstance(data, dict) and "summary" in data and "frames" in data:
        s      = data["summary"]
        frames = data["frames"]

        channels    = s.get("frames_by_channel", {})
        frame_types = dict(sorted(s.get("frames_by_type", {}).items(), key=lambda x: -x[1])[:12])
        top_talkers = dict(s.get("top_talkers", [])[:8])
        categories  = s.get("frames_by_category", {})
        rssi_hist   = s.get("rssi_histogram", {})
        data_rates  = s.get("data_rates", {})
        duration_sec = s.get("capture_duration_sec", 0)
        net_rows    = s.get("networks", [])

        for n in net_rows:
            if "beacons" not in n and "frames" in n:
                n["beacons"] = n.pop("frames")

        return {
            "mode":             "pcapng",
            "total_frames":     s.get("total_frames", len(frames)),
            "total_networks":   s.get("total_networks", len(net_rows)),
            "avg_rssi":         s.get("avg_rssi"),
            "min_rssi":         s.get("min_rssi"),
            "max_rssi":         s.get("max_rssi"),
            "parsed_at":        s.get("parsed_at", "—"),
            "capture_duration": f"{duration_sec // 60}m {duration_sec % 60}s" if duration_sec else "—",
            "channels":         channels,
            "categories":       categories,
            "frame_types":      frame_types,
            "rssi_hist":        rssi_hist,
            "data_rates":       data_rates,
            "top_talkers":      top_talkers,
            "networks":         net_rows,
        }

    # ── Legacy format: plain list ────────────────────────────────
    if not isinstance(data, list):
        data = []

    type_counter    = defaultdict(int)
    channel_counter = defaultdict(int)
    mac_counter     = defaultdict(int)
    bssid_counter   = defaultdict(int)
    rssi_values     = []

    for f in data:
        type_counter[f.get("frame_type", "Unknown")] += 1
        src = f.get("src_mac", "")
        if src and src != "??:??:??:??:??:??":
            mac_counter[src] += 1
        bssid = f.get("bssid", "")
        if bssid and bssid != "??:??:??:??:??:??":
            bssid_counter[bssid] += 1
        if f.get("rssi") is not None:
            rssi_values.append(f["rssi"])
        if f.get("channel"):
            channel_counter[str(f["channel"])] += 1

    frame_types = dict(sorted(type_counter.items(), key=lambda x: -x[1])[:12])
    top_talkers = dict(sorted(mac_counter.items(), key=lambda x: -x[1])[:8])
    top_bssids  = dict(sorted(bssid_counter.items(), key=lambda x: -x[1])[:8])

    mgmt_keywords = {"Beacon", "Probe", "Association", "Authentication",
                     "Deauthentication", "Disassociation", "Reassociation"}
    ctrl_keywords = {"ACK", "RTS", "CTS", "Block Ack", "PS-Poll"}
    categories = {"management": 0, "control": 0, "data": 0, "unknown": 0}
    for ft, count in type_counter.items():
        if any(k in ft for k in mgmt_keywords):
            categories["management"] += count
        elif any(k in ft for k in ctrl_keywords):
            categories["control"] += count
        elif "Data" in ft:
            categories["data"] += count
        else:
            categories["unknown"] += count

    avg_rssi = round(sum(rssi_values)/len(rssi_values), 2) if rssi_values else None

    return {
        "mode":             "pcap",
        "total_frames":     len(data),
        "total_networks":   len(top_bssids),
        "avg_rssi":         avg_rssi,
        "min_rssi":         min(rssi_values) if rssi_values else None,
        "max_rssi":         max(rssi_values) if rssi_values else None,
        "parsed_at":        datetime.now(timezone.utc).isoformat(),
        "capture_duration": "—",
        "channels":         dict(channel_counter),
        "categories":       categories,
        "frame_types":      frame_types,
        "rssi_hist":        {},
        "data_rates":       {},
        "top_talkers":      top_talkers,
        "networks":         [{"ssid": "—", "bssid": b, "channel": "—",
                              "rssi_min": "—", "rssi_max": "—",
                              "rssi_avg": "—", "encryption": "—",
                              "network_type": "—", "beacons": c}
                             for b, c in top_bssids.items()],
    }


# -----------------------------------------------------------------
# Chart helpers (inline Chart.js via CDN)
# -----------------------------------------------------------------

def _bar_chart(canvas_id: str, labels: list, values: list,
               color: str = "#4f8ef7", label: str = "Frames") -> str:
    labels_js = json.dumps(labels)
    values_js = json.dumps(values)
    return f"""
    new Chart(document.getElementById('{canvas_id}'), {{
        type: 'bar',
        data: {{
            labels: {labels_js},
            datasets: [{{ label: '{label}', data: {values_js},
                backgroundColor: '{color}', borderRadius: 4 }}]
        }},
        options: {{
            responsive: true,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{ y: {{ beginAtZero: true, ticks: {{ color:'#ccc' }},
                            grid: {{ color:'#333' }} }},
                       x: {{ ticks: {{ color:'#ccc' }},
                            grid: {{ color:'#333' }} }} }}
        }}
    }});"""


def _doughnut_chart(canvas_id: str, labels: list, values: list) -> str:
    COLORS = ["#4f8ef7", "#f7914f", "#4ff7a0", "#f74f4f",
              "#c44ff7", "#f7e24f", "#4ff7f7", "#f74fc4"]
    colors_js = json.dumps(COLORS[:len(labels)])
    labels_js = json.dumps(labels)
    values_js = json.dumps(values)
    return f"""
    new Chart(document.getElementById('{canvas_id}'), {{
        type: 'doughnut',
        data: {{
            labels: {labels_js},
            datasets: [{{ data: {values_js},
                backgroundColor: {colors_js}, borderWidth: 2,
                borderColor: '#1a1a2e' }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                legend: {{ position: 'bottom',
                           labels: {{ color:'#ccc', padding: 12 }} }}
            }}
        }}
    }});"""


# -----------------------------------------------------------------
# HTML Template
# -----------------------------------------------------------------

def build_html(ctx: dict, source_file: str) -> str:

    # --- Charts JS ---
    charts_js = ""

    if ctx["channels"]:
        ch_labels = [f"CH {k}" for k in ctx["channels"].keys()]
        ch_values = list(ctx["channels"].values())
        charts_js += _bar_chart("channelChart", ch_labels, ch_values, "#4f8ef7", "Frames")

    if ctx["categories"]:
        cat_labels = list(ctx["categories"].keys())
        cat_values = list(ctx["categories"].values())
        charts_js += _doughnut_chart("categoryChart", cat_labels, cat_values)

    if ctx["frame_types"]:
        ft_labels = list(ctx["frame_types"].keys())
        ft_values = list(ctx["frame_types"].values())
        charts_js += _bar_chart("frameTypeChart", ft_labels, ft_values, "#f7914f", "Frames")

    if ctx["rssi_hist"]:
        rssi_labels = [f"{k} dBm" for k in ctx["rssi_hist"].keys()]
        rssi_values = list(ctx["rssi_hist"].values())
        charts_js += _bar_chart("rssiChart", rssi_labels, rssi_values, "#4ff7a0", "Frames")

    if ctx["top_talkers"]:
        tt_labels = list(ctx["top_talkers"].keys())
        tt_values = list(ctx["top_talkers"].values())
        charts_js += _bar_chart("talkersChart", tt_labels, tt_values, "#c44ff7", "Frames")

    if ctx.get("data_rates"):
        dr_labels = list(ctx["data_rates"].keys())
        dr_values = list(ctx["data_rates"].values())
        charts_js += _bar_chart("rateChart", dr_labels, dr_values, "#f7e24f", "Frames")

    # --- Network rows ---
    net_rows_html = ""
    for n in ctx["networks"]:
        enc = n.get("encryption", "—") or "—"
        enc_color = {
            "WPA2": "#4ff7a0", "WPA": "#f7e24f",
            "WEP":  "#f7914f", "Open": "#888"
        }.get(enc, "#888")
        avg_rssi = n.get("rssi_avg", "—")
        net_rows_html += f"""
        <tr>
            <td><strong>{n['ssid']}</strong></td>
            <td><code>{n['bssid']}</code></td>
            <td style="text-align:center">{n['channel']}</td>
            <td style="text-align:center;color:#aaa">{n.get('rssi_min','—')}</td>
            <td style="text-align:center;color:#aaa">{n.get('rssi_max','—')}</td>
            <td style="text-align:center;color:#4f8ef7"><strong>{avg_rssi}</strong></td>
            <td style="text-align:center"><span style="color:{enc_color};font-weight:600">{enc}</span></td>
            <td style="text-align:center">{n.get('network_type','—')}</td>
            <td style="text-align:right">{n['beacons']:,}</td>
        </tr>"""

    # --- RSSI section (only for analyzer mode) ---
    rssi_section = ""
    if ctx["rssi_hist"]:
        rssi_section = """
        <div class="card">
            <h2>RSSI Distribution</h2>
            <p class="subtitle">Signal strength spread across all captured frames (dBm)</p>
            <canvas id="rssiChart" height="100"></canvas>
        </div>"""

    # --- Channel section ---
    channel_section = ""
    if ctx["channels"]:
        channel_section = """
        <div class="card">
            <h2>Frames per Channel</h2>
            <p class="subtitle">802.11 channel activity distribution</p>
            <canvas id="channelChart" height="100"></canvas>
        </div>"""

    # --- RSSI stat cards ---
    rssi_cards = ""
    if ctx["avg_rssi"] is not None:
        rssi_cards = f"""
        <div class="stat-card">
            <div class="stat-value">{ctx['avg_rssi']} dBm</div>
            <div class="stat-label">Avg RSSI</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{ctx['min_rssi']} / {ctx['max_rssi']}</div>
            <div class="stat-label">RSSI Range (dBm)</div>
        </div>"""

    # --- Capture duration stat card ---
    duration_card = ""
    if ctx.get("capture_duration") and ctx["capture_duration"] != "—":
        duration_card = f"""
        <div class="stat-card">
            <div class="stat-value">{ctx['capture_duration']}</div>
            <div class="stat-label">Capture Duration</div>
        </div>"""

    # --- Data rate section ---
    rate_section = ""
    if ctx.get("data_rates"):
        rate_section = """
        <div class="card" style="margin-bottom:1.5rem">
            <h2>Data Rate Distribution</h2>
            <p class="subtitle">PHY layer transmission rates observed (Mbps)</p>
            <canvas id="rateChart" height="80"></canvas>
        </div>"""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ESP32 WiFi Analysis Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f0f1a;
    color: #e0e0e0;
    padding: 2rem;
    line-height: 1.6;
  }}

  .header {{
    border-bottom: 1px solid #2a2a4a;
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}

  .header h1 {{
    font-size: 1.8rem;
    color: #4f8ef7;
    letter-spacing: -0.5px;
  }}

  .header .meta {{
    font-size: 0.85rem;
    color: #666;
    margin-top: 0.4rem;
  }}

  .badge {{
    display: inline-block;
    background: #1a1a3a;
    border: 1px solid #2a2a5a;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    color: #4f8ef7;
    margin-left: 0.5rem;
    vertical-align: middle;
  }}

  .stats-row {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}

  .stat-card {{
    background: #1a1a2e;
    border: 1px solid #2a2a4a;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
  }}

  .stat-value {{
    font-size: 1.6rem;
    font-weight: 700;
    color: #4f8ef7;
  }}

  .stat-label {{
    font-size: 0.8rem;
    color: #888;
    margin-top: 0.2rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  .grid-2 {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }}

  .card {{
    background: #1a1a2e;
    border: 1px solid #2a2a4a;
    border-radius: 8px;
    padding: 1.5rem;
  }}

  .card h2 {{
    font-size: 1rem;
    font-weight: 600;
    color: #ccc;
    margin-bottom: 0.3rem;
  }}

  .subtitle {{
    font-size: 0.78rem;
    color: #555;
    margin-bottom: 1.2rem;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }}

  thead th {{
    text-align: left;
    color: #888;
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #2a2a4a;
  }}

  tbody tr:hover {{ background: #20203a; }}

  tbody td {{
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #1e1e38;
    color: #ccc;
  }}

  code {{
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 0.82rem;
    color: #4ff7a0;
  }}

  .footer {{
    margin-top: 2.5rem;
    padding-top: 1rem;
    border-top: 1px solid #2a2a4a;
    font-size: 0.75rem;
    color: #444;
    text-align: center;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>📡 ESP32 WiFi Analysis Report <span class="badge">{ctx['mode'].upper()}</span></h1>
  <div class="meta">
    Source: <code>{source_file}</code> &nbsp;·&nbsp;
    Captured at: {ctx['parsed_at']} &nbsp;·&nbsp;
    Generated: {generated_at}
  </div>
</div>

<div class="stats-row">
  <div class="stat-card">
    <div class="stat-value">{ctx['total_frames']:,}</div>
    <div class="stat-label">Total Frames</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{ctx['total_networks']}</div>
    <div class="stat-label">Networks Detected</div>
  </div>
  {rssi_cards}
  {duration_card}
</div>

<div class="grid-2">
  {channel_section}
  <div class="card">
    <h2>Frame Categories</h2>
    <p class="subtitle">Management · Control · Data distribution</p>
    <canvas id="categoryChart" height="200"></canvas>
  </div>
</div>

<div class="card" style="margin-bottom:1.5rem">
  <h2>Frame Type Breakdown</h2>
  <p class="subtitle">Top 802.11 frame subtypes observed during capture</p>
  <canvas id="frameTypeChart" height="80"></canvas>
</div>

{rssi_section}

{rate_section}

<div class="card" style="margin-bottom:1.5rem">
  <h2>Top Transmitters</h2>
  <p class="subtitle">MAC addresses with the highest frame count</p>
  <canvas id="talkersChart" height="80"></canvas>
</div>

<div class="card">
  <h2>Discovered Networks</h2>
  <p class="subtitle">Access points observed during the capture session</p>
  <table>
    <thead>
      <tr>
        <th>SSID</th><th>BSSID</th><th>CH</th>
        <th>RSSI Min</th><th>RSSI Max</th><th>Avg RSSI</th>
        <th>Encryption</th><th>Type</th><th style="text-align:right">Frames</th>
      </tr>
    </thead>
    <tbody>
      {net_rows_html if net_rows_html else '<tr><td colspan="6" style="color:#555;text-align:center;padding:1rem">No network data available</td></tr>'}
    </tbody>
  </table>
</div>

<div class="footer">
  ESP32 Wireless Communications Research Lab &nbsp;·&nbsp;
  Educational use only &nbsp;·&nbsp;
  Generated by report_generator.py
</div>

<script>
{charts_js}
</script>
</body>
</html>"""


# -----------------------------------------------------------------
# CLI
# -----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate an HTML report from wifi_analyzer.py or pcap_parser.py JSON output."
    )
    parser.add_argument("--input",  required=True, help="JSON file from wifi_analyzer or pcap_parser")
    parser.add_argument("--output", default="report.html", help="Output HTML file (default: report.html)")
    parser.add_argument("--mode",   choices=["analyzer", "pcap"], default="analyzer",
                        help="Input format: 'analyzer' (default) or 'pcap'")
    args = parser.parse_args()

    print(f"[*] Loading {args.input} ...")
    with open(args.input, "r") as f:
        raw = json.load(f)

    # Auto-detect format: enriched pcap_parser output (dict with summary+frames)
    # takes priority over --mode flag — no manual flag needed for new format.
    if isinstance(raw, dict) and "summary" in raw and "frames" in raw:
        print("[*] Detected: enriched pcap_parser format")
        ctx = process_pcap_data(raw)

    elif args.mode == "pcap":
        if not isinstance(raw, list):
            print("[!] Error: expected a JSON array or enriched dict from pcap_parser.py")
            return
        ctx = process_pcap_data(raw)

    else:
        if not isinstance(raw, dict):
            print("[!] Error: analyzer mode expects a JSON object (output from wifi_analyzer.py)")
            return
        ctx = process_analyzer_data(raw)

    print(f"[*] Building report ...")
    html = build_html(ctx, source_file=Path(args.input).name)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Report saved to: {args.output}")
    print(f"    Open it in any browser — no server needed.")


if __name__ == "__main__":
    main()
