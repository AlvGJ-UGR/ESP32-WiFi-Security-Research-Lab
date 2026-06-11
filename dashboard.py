"""
dashboard.py
------------
Streamlit live dashboard for ESP32 WiFi capture analysis.

Loads a frames JSON file produced by pcap_parser.py and displays
interactive visualizations with auto-refresh support.

Requirements:
    pip install streamlit plotly pandas

Usage:
    streamlit run analyzer/dashboard.py
    streamlit run analyzer/dashboard.py -- --file captures/frames.json
    streamlit run analyzer/dashboard.py -- --live http://192.168.4.1/api/pcap/download
"""

import json
import time
import argparse
import sys
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

try:
    import streamlit as st
    import plotly.express as px
    import plotly.graph_objects as go
    import pandas as pd
except ImportError:
    print("[!] Dashboard requires: pip install streamlit plotly pandas")
    print("    Then run: streamlit run analyzer/dashboard.py")
    sys.exit(1)

# Optional OUI resolution
try:
    from oui_lookup import resolve as oui_resolve
    OUI_AVAILABLE = True
except ImportError:
    OUI_AVAILABLE = False
    def oui_resolve(mac): return mac


# ─────────────────────────────────────────────────────────────────
# Page config — must be first Streamlit call
# ─────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="ESP32 WiFi Research Lab",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────
# Custom CSS
# ─────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    .main { background-color: #0f0f1a; }
    .stMetric { background: #1a1a2e; border: 1px solid #2a2a4a;
                border-radius: 8px; padding: 1rem; }
    .stMetric label { color: #888 !important; font-size: 0.78rem;
                      text-transform: uppercase; letter-spacing: 0.05em; }
    .stMetric [data-testid="stMetricValue"] { color: #4f8ef7 !important;
                                               font-weight: 700; }
    h1, h2, h3 { color: #e0e0e0 !important; }
    .stDataFrame { background: #1a1a2e; }
    div[data-testid="stSidebar"] { background: #12122a; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────

COLORS = ["#4f8ef7", "#f7914f", "#4ff7a0", "#f74f4f",
          "#c44ff7", "#f7e24f", "#4ff7f7", "#f74fc4",
          "#7fff7f", "#ff7f7f", "#7f7fff", "#ffbf7f"]


def load_json(path: str) -> dict | list | None:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Failed to load file: {e}")
        return None


def load_live(url: str) -> dict | None:
    """Download a .pcap from the ESP32 HTTP interface and parse it on the fly."""
    try:
        import urllib.request, tempfile, os
        sys.path.insert(0, str(Path(__file__).parent))
        from pcap_parser import iter_frames, build_summary

        with urllib.request.urlopen(url, timeout=10) as resp:
            data = resp.read()

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(data)
            tmp_path = f.name

        try:
            frames = list(iter_frames(tmp_path))
            summary = build_summary(frames)
            return {"summary": summary, "frames": []}
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        st.error(f"Failed to fetch live capture: {e}")
        return None


def extract_context(data: dict | list) -> tuple[dict, list]:
    """Return (summary_dict, frames_list) from any input format."""
    if isinstance(data, dict) and "summary" in data:
        return data["summary"], data.get("frames", [])
    if isinstance(data, list):
        # Build summary from plain frame list
        sys.path.insert(0, str(Path(__file__).parent))
        try:
            from pcap_parser import build_summary, Frame
            from dataclasses import fields
            field_names = {f.name for f in fields(Frame)}
            # Convert dicts to Frame objects where possible
            from pcap_parser import Frame as F
            frame_objs = []
            for fr in data:
                try:
                    frame_objs.append(F(**{k: fr.get(k) for k in field_names}))
                except Exception:
                    pass
            summary = build_summary(frame_objs) if frame_objs else {}
        except Exception:
            summary = {}
        return summary, data
    return {}, []


# ─────────────────────────────────────────────────────────────────
# Chart helpers
# ─────────────────────────────────────────────────────────────────

PLOTLY_DARK = dict(
    paper_bgcolor="#1a1a2e",
    plot_bgcolor="#1a1a2e",
    font=dict(color="#ccc"),
    xaxis=dict(gridcolor="#2a2a4a", zerolinecolor="#2a2a4a"),
    yaxis=dict(gridcolor="#2a2a4a", zerolinecolor="#2a2a4a"),
    margin=dict(l=20, r=20, t=40, b=20),
)


def bar(labels, values, title, color="#4f8ef7", horizontal=False):
    orientation = "h" if horizontal else "v"
    x, y = (values, labels) if horizontal else (labels, values)
    fig = go.Figure(go.Bar(
        x=x, y=y,
        orientation=orientation,
        marker_color=color,
        marker_line_width=0,
    ))
    fig.update_layout(title=title, **PLOTLY_DARK)
    return fig


def pie(labels, values, title):
    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        hole=0.45,
        marker_colors=COLORS[:len(labels)],
        textfont=dict(color="#ccc"),
    ))
    fig.update_layout(title=title, **PLOTLY_DARK,
                      legend=dict(font=dict(color="#ccc")))
    return fig


def scatter_rssi(frames: list[dict]):
    """RSSI over time scatter plot."""
    pts = [(f["ts_sec"], f["rssi"], f.get("frame_type", ""))
           for f in frames if f.get("rssi") is not None and f.get("ts_sec")]
    if not pts:
        return None
    df = pd.DataFrame(pts, columns=["ts", "rssi", "type"])
    df["time"] = pd.to_datetime(df["ts"], unit="s")
    fig = px.scatter(df, x="time", y="rssi", color="type",
                     title="RSSI over Capture Time",
                     color_discrete_sequence=COLORS)
    fig.update_layout(**PLOTLY_DARK)
    return fig


# ─────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 📡 ESP32 WiFi Lab")
    st.markdown("---")

    source_mode = st.radio("Data source", ["File", "Live (ESP32)"], index=0)

    if source_mode == "File":
        uploaded = st.file_uploader("Upload frames.json", type=["json"])
        file_path = st.text_input("Or enter local path",
                                  placeholder="captures/frames.json")
        live_url = None
    else:
        live_url = st.text_input("ESP32 PCAP URL",
                                 value="http://192.168.4.1/api/pcap/download")
        uploaded = None
        file_path = None

    st.markdown("---")
    auto_refresh = st.checkbox("Auto-refresh (live mode)", value=False)
    refresh_interval = st.slider("Refresh interval (s)", 5, 60, 15,
                                 disabled=not auto_refresh)
    frame_limit = st.number_input("Max frames to show in table", 50, 5000, 200)
    st.markdown("---")
    if OUI_AVAILABLE:
        st.success("✅ OUI lookup active")
    else:
        st.warning("⚠️ oui_lookup.py not found")

    st.markdown("""
    <small style='color:#555'>
    ESP32 WiFi Security Research Lab<br/>
    Educational use only
    </small>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# Load data
# ─────────────────────────────────────────────────────────────────

data = None

if uploaded is not None:
    data = json.load(uploaded)
elif file_path:
    data = load_json(file_path)
elif live_url:
    data = load_live(live_url)

if data is None:
    st.markdown("""
    <div style='text-align:center;padding:4rem;color:#555'>
        <h1 style='color:#4f8ef7;font-size:3rem'>📡</h1>
        <h2 style='color:#888'>ESP32 WiFi Security Research Lab</h2>
        <p>Upload a <code>frames.json</code> file or connect to your ESP32<br/>
        to start analyzing captures.</p>
        <br/>
        <p style='font-size:0.85rem'>
        Generate a capture file with:<br/>
        <code>python analyzer/pcap_parser.py --file capture.pcapng --export frames.json</code>
        </p>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

summary, frames = extract_context(data)

# ─────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────

st.markdown("# 📡 ESP32 WiFi Security Research Lab")
st.markdown(f"*Dashboard generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
st.markdown("---")

# ─────────────────────────────────────────────────────────────────
# Top metrics
# ─────────────────────────────────────────────────────────────────

total    = summary.get("total_frames", len(frames))
networks = summary.get("total_networks", 0)
avg_rssi = summary.get("avg_rssi")
min_rssi = summary.get("min_rssi")
max_rssi = summary.get("max_rssi")
duration = summary.get("capture_duration_sec", 0)
dur_str  = f"{duration // 60}m {duration % 60}s" if duration else "—"

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Frames",      f"{total:,}")
col2.metric("Networks Found",    networks)
col3.metric("Avg RSSI",          f"{avg_rssi} dBm" if avg_rssi else "—")
col4.metric("RSSI Range",        f"{min_rssi} / {max_rssi}" if min_rssi else "—")
col5.metric("Capture Duration",  dur_str)

st.markdown("---")

# ─────────────────────────────────────────────────────────────────
# Row 1: Channel + Category
# ─────────────────────────────────────────────────────────────────

col_left, col_right = st.columns(2)

with col_left:
    channels = summary.get("frames_by_channel", {})
    if channels:
        ch_labels = [f"CH {k}" for k in channels.keys()]
        ch_values = list(channels.values())
        st.plotly_chart(bar(ch_labels, ch_values, "Frames per Channel", "#4f8ef7"),
                        use_container_width=True)
    else:
        st.info("No channel data available")

with col_right:
    cats = summary.get("frames_by_category", {})
    if cats:
        st.plotly_chart(pie(list(cats.keys()), list(cats.values()),
                            "Frame Category Distribution"),
                        use_container_width=True)
    else:
        st.info("No category data available")

# ─────────────────────────────────────────────────────────────────
# Row 2: Frame types + RSSI histogram
# ─────────────────────────────────────────────────────────────────

col_left2, col_right2 = st.columns(2)

with col_left2:
    ftypes = summary.get("frames_by_type", {})
    if ftypes:
        ft_labels = list(ftypes.keys())
        ft_values = list(ftypes.values())
        st.plotly_chart(bar(ft_labels, ft_values, "Frame Type Breakdown",
                            "#f7914f", horizontal=True),
                        use_container_width=True)

with col_right2:
    rssi_hist = summary.get("rssi_histogram", {})
    if rssi_hist:
        rh_labels = [f"{k} dBm" for k in rssi_hist.keys()]
        rh_values = list(rssi_hist.values())
        st.plotly_chart(bar(rh_labels, rh_values, "RSSI Distribution", "#4ff7a0"),
                        use_container_width=True)

# ─────────────────────────────────────────────────────────────────
# Row 3: Data rates + Top talkers
# ─────────────────────────────────────────────────────────────────

col_left3, col_right3 = st.columns(2)

with col_left3:
    rates = summary.get("data_rates", {})
    if rates:
        st.plotly_chart(bar(list(rates.keys()), list(rates.values()),
                            "Data Rate Distribution (Mbps)", "#f7e24f"),
                        use_container_width=True)

with col_right3:
    talkers = dict(summary.get("top_talkers", []))
    if talkers:
        if OUI_AVAILABLE:
            talker_labels = [f"{oui_resolve(m)[:22]}\n{m}" for m in talkers.keys()]
        else:
            talker_labels = list(talkers.keys())
        st.plotly_chart(bar(talker_labels, list(talkers.values()),
                            "Top Transmitters", "#c44ff7", horizontal=True),
                        use_container_width=True)

# ─────────────────────────────────────────────────────────────────
# RSSI scatter over time (if frame-level data available)
# ─────────────────────────────────────────────────────────────────

if frames:
    fig_scatter = scatter_rssi(frames[:5000])
    if fig_scatter:
        st.plotly_chart(fig_scatter, use_container_width=True)

# ─────────────────────────────────────────────────────────────────
# Networks table
# ─────────────────────────────────────────────────────────────────

st.markdown("### 🔍 Discovered Networks")

net_rows = summary.get("networks", [])
if net_rows:
    df_nets = pd.DataFrame(net_rows)
    # Add vendor column if OUI available
    if OUI_AVAILABLE and "bssid" in df_nets.columns:
        df_nets.insert(2, "vendor", df_nets["bssid"].apply(oui_resolve))
    # Colour-code encryption
    enc_map = {"WPA2": "🟢", "WPA": "🟡", "WEP": "🟠", "Open": "⚪"}
    if "encryption" in df_nets.columns:
        df_nets["encryption"] = df_nets["encryption"].apply(
            lambda e: f"{enc_map.get(e, '❓')} {e}"
        )
    # Drop internal fields
    for col in ["rssi_list", "beacon_interval"]:
        if col in df_nets.columns:
            df_nets.drop(columns=[col], inplace=True)

    st.dataframe(df_nets, use_container_width=True, height=300)
else:
    st.info("No network data in this capture.")

# ─────────────────────────────────────────────────────────────────
# Frame-level table (optional, paginated)
# ─────────────────────────────────────────────────────────────────

if frames:
    with st.expander(f"📋 Frame-level data (showing first {frame_limit})"):
        df_frames = pd.DataFrame(frames[:int(frame_limit)])
        if OUI_AVAILABLE and "src_mac" in df_frames.columns:
            df_frames.insert(
                df_frames.columns.get_loc("src_mac") + 1,
                "src_vendor",
                df_frames["src_mac"].apply(oui_resolve)
            )
        st.dataframe(df_frames, use_container_width=True, height=400)

# ─────────────────────────────────────────────────────────────────
# Auto-refresh
# ─────────────────────────────────────────────────────────────────

if auto_refresh and live_url:
    time.sleep(refresh_interval)
    st.rerun()

# ─────────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────────

st.markdown("---")
st.markdown("""
<div style='text-align:center;color:#444;font-size:0.75rem'>
ESP32 WiFi Security Research Lab · Educational use only ·
<a href='https://github.com/AlvGJ-UGR/ESP32-WiFi-Security-Research-Lab'
   style='color:#4f8ef7'>GitHub</a>
</div>
""", unsafe_allow_html=True)
