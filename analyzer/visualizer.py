"""
analyzer/visualizer.py
-----------------------
Matplotlib-based visualisations for PCAP analysis results.

Produces:
  - Channel utilisation bar chart
  - AP encryption distribution pie chart
  - Client activity timeline
"""

import os
from collections import Counter

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import numpy as np
    MPL = True
except ImportError:
    MPL = False

_BG    = "#0D0D1A"
_TEXT  = "#E0E0E0"
_CYAN  = "#00B4D8"
_VIO   = "#7B61FF"
_MAG   = "#F72585"
_AMB   = "#FFB703"
_GREEN = "#06D6A0"

_ENC_COLORS = {
    "WPA2":     _CYAN,
    "WPA":      _VIO,
    "OPEN/WEP": _MAG,
}


def _check_mpl():
    if not MPL:
        print("[WARN] matplotlib not installed — skipping plot")
        return False
    return True


def plot_channel_utilization(result: dict, save_path: str = None) -> None:
    """Bar chart: number of APs per 2.4 GHz / 5 GHz channel."""
    if not _check_mpl():
        return

    channels = [ap["channel"] for ap in result["aps"] if ap["channel"]]
    if not channels:
        print("[WARN] No channel information found in capture.")
        return

    counts = Counter(channels)
    # Split 2.4 GHz (1-14) and 5 GHz (36+)
    ch_24 = {ch: counts[ch] for ch in sorted(counts) if ch <= 14}
    ch_5  = {ch: counts[ch] for ch in sorted(counts) if ch > 14}

    fig, axes = plt.subplots(1, 2 if ch_5 else 1, figsize=(12, 5), facecolor=_BG)
    if not isinstance(axes, (list, np.ndarray)):
        axes = [axes]

    for ax, (band_label, data) in zip(axes, [("2.4 GHz", ch_24), ("5 GHz", ch_5)]):
        if not data:
            continue
        ax.set_facecolor(_BG)
        bars = ax.bar(list(data.keys()), list(data.values()), color=_CYAN,
                      edgecolor=_VIO, linewidth=0.8)
        ax.set_xlabel("Channel", color=_TEXT, fontsize=11)
        ax.set_ylabel("Access Points", color=_TEXT, fontsize=11)
        ax.set_title(f"Channel Utilisation — {band_label}", color=_TEXT, fontsize=12, pad=8)
        ax.tick_params(colors=_TEXT)
        for sp in ax.spines.values():
            sp.set_edgecolor("#333344")
        ax.grid(axis="y", color="#2A2A3E", linewidth=0.6)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.05, str(int(h)),
                    ha="center", va="bottom", color=_TEXT, fontsize=9)

    fig.suptitle("Wi-Fi Channel Utilisation", color=_TEXT, fontsize=14, y=1.01)
    plt.tight_layout()

    path = save_path or os.path.join("reports", "channel_utilization.png")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=_BG)
    print(f"[plot] Saved → {path}")
    plt.close(fig)


def plot_encryption_distribution(result: dict, save_path: str = None) -> None:
    """Pie chart: encryption type breakdown across all detected APs."""
    if not _check_mpl():
        return

    enc_counts = Counter(ap["enc"] for ap in result["aps"])
    if not enc_counts:
        print("[WARN] No encryption data.")
        return

    labels = list(enc_counts.keys())
    sizes  = list(enc_counts.values())
    colors = [_ENC_COLORS.get(l, _AMB) for l in labels]

    fig, ax = plt.subplots(figsize=(6, 6), facecolor=_BG)
    ax.set_facecolor(_BG)
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors,
        autopct="%1.1f%%", startangle=140,
        wedgeprops={"edgecolor": _BG, "linewidth": 2},
    )
    for t in texts + autotexts:
        t.set_color(_TEXT)
        t.set_fontsize(11)

    ax.set_title("Encryption Distribution", color=_TEXT, fontsize=13, pad=12)
    plt.tight_layout()

    path = save_path or os.path.join("reports", "encryption_distribution.png")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=_BG)
    print(f"[plot] Saved → {path}")
    plt.close(fig)


def plot_all(result: dict, out_dir: str = "reports") -> None:
    """Generate all available plots and save to out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    plot_channel_utilization(result,       os.path.join(out_dir, "channel_utilization.png"))
    plot_encryption_distribution(result,   os.path.join(out_dir, "encryption_distribution.png"))
