"""
analyzer/visualizer.py
-----------------------
Matplotlib-based visualisations for PCAP analysis results.

Produces:
  - Channel utilisation bar chart  (2.4 GHz / 5 GHz split)
  - AP encryption distribution pie chart
  - Client activity timeline (top N clients by frame count)
  - Beacon rate over time (APs activity heatmap)
  - Combined dashboard (all plots in one figure)

Compatible with both the legacy dict-based result and the new
AnalysisResult / AccessPoint / Client dataclasses from pcap_analyzer.py.

Usage (standalone)
------------------
    from analyzer.visualizer import plot_all
    plot_all(result, out_dir="reports")
"""

from __future__ import annotations

import logging
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Union

log = logging.getLogger(__name__)

try:
    import matplotlib
    matplotlib.use("Agg")           # non-interactive backend; safe for servers
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import matplotlib.ticker as mticker
    from matplotlib.patches import FancyBboxPatch
    import numpy as np
    MPL = True
except ImportError:
    MPL = False

# ── type alias ────────────────────────────────────────────────────────────────
# Accept either the new AnalysisResult dataclass or a plain dict (legacy).
ResultLike = Any

# ── colour palette ────────────────────────────────────────────────────────────
_BG    = "#0D0D1A"
_BG2   = "#12122A"       # slightly lighter panel bg
_TEXT  = "#E0E0E0"
_DIM   = "#888899"
_CYAN  = "#00B4D8"
_VIO   = "#7B61FF"
_MAG   = "#F72585"
_AMB   = "#FFB703"
_GREEN = "#06D6A0"
_GRID  = "#1E1E30"

_ENC_COLORS: dict[str, str] = {
    "WPA3":     _GREEN,
    "WPA2":     _CYAN,
    "WPA":      _VIO,
    "OPEN/WEP": _MAG,
}

_BAND_COLORS = {
    "2.4 GHz": _CYAN,
    "5 GHz":   _AMB,
    "6 GHz":   _GREEN,
}

# ── internal helpers ──────────────────────────────────────────────────────────

def _require_mpl(fn_name: str) -> bool:
    if not MPL:
        log.warning("%s: matplotlib not installed — skipping", fn_name)
    return MPL


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Unified attribute/key access for dataclass or dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _ap_list(result: ResultLike) -> list[Any]:
    return _get(result, "aps", [])


def _client_list(result: ResultLike) -> list[Any]:
    return _get(result, "clients", [])


def _style_ax(ax, title: str = "", xlabel: str = "", ylabel: str = "") -> None:
    """Apply the dark theme to a single Axes."""
    ax.set_facecolor(_BG2)
    ax.tick_params(colors=_TEXT, labelsize=9)
    ax.xaxis.label.set_color(_TEXT)
    ax.yaxis.label.set_color(_TEXT)
    ax.title.set_color(_TEXT)
    for sp in ax.spines.values():
        sp.set_edgecolor(_GRID)
    ax.grid(axis="y", color=_GRID, linewidth=0.6, linestyle="--")
    if title:
        ax.set_title(title, fontsize=11, pad=8)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=10)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=10)


def _bar_labels(ax, bars, fmt: str = "{:.0f}") -> None:
    """Annotate each bar with its height value."""
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + 0.05,
                fmt.format(h),
                ha="center", va="bottom",
                color=_TEXT, fontsize=8,
            )


def _save(fig: "plt.Figure", path: str, dpi: int = 150) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, bbox_inches="tight", facecolor=_BG)
    log.info("[plot] Saved → %s", path)
    plt.close(fig)


def _default_path(out_dir: str, filename: str) -> str:
    return str(Path(out_dir) / filename)


# ── plots ─────────────────────────────────────────────────────────────────────

def plot_channel_utilization(
    result: ResultLike,
    save_path: str | None = None,
    out_dir: str = "reports",
    show: bool = False,
) -> str | None:
    """
    Bar chart: number of AP beacons per channel, split by band.

    Returns the saved file path, or None if skipped.
    """
    if not _require_mpl("plot_channel_utilization"):
        return None

    aps = _ap_list(result)
    channels = [_get(ap, "channel") for ap in aps if _get(ap, "channel") is not None]
    if not channels:
        log.warning("No channel information found in capture.")
        return None

    counts = Counter(channels)

    # Band buckets: 2.4 GHz (1-14), 5 GHz (36-177), 6 GHz (1-233 mapped > 177)
    bands: dict[str, dict[int, int]] = {
        "2.4 GHz": {ch: counts[ch] for ch in sorted(counts) if 1  <= ch <= 14},
        "5 GHz":   {ch: counts[ch] for ch in sorted(counts) if 36 <= ch <= 177},
        "6 GHz":   {ch: counts[ch] for ch in sorted(counts) if ch > 177},
    }
    active_bands = [(label, data) for label, data in bands.items() if data]
    n = len(active_bands)

    fig, axes = plt.subplots(1, n, figsize=(6 * n, 5), facecolor=_BG)
    if n == 1:
        axes = [axes]

    for ax, (band_label, data) in zip(axes, active_bands):
        color = _BAND_COLORS.get(band_label, _CYAN)
        bars  = ax.bar(
            list(data.keys()), list(data.values()),
            color=color, edgecolor=_VIO, linewidth=0.7, width=0.7,
        )
        _style_ax(ax, title=f"Channel Utilisation — {band_label}",
                  xlabel="Channel", ylabel="Access Points")
        ax.xaxis.set_major_locator(mticker.MultipleLocator(1))
        _bar_labels(ax, bars)

    fig.suptitle("Wi-Fi Channel Utilisation", color=_TEXT, fontsize=14, y=1.02)
    plt.tight_layout()

    path = save_path or _default_path(out_dir, "channel_utilization.png")
    _save(fig, path)
    if show:
        plt.show()
    return path


def plot_encryption_distribution(
    result: ResultLike,
    save_path: str | None = None,
    out_dir: str = "reports",
    show: bool = False,
) -> str | None:
    """
    Donut chart: encryption type breakdown across all detected APs.

    Returns the saved file path, or None if skipped.
    """
    if not _require_mpl("plot_encryption_distribution"):
        return None

    aps = _ap_list(result)
    enc_counts = Counter(_get(ap, "enc", "UNKNOWN") for ap in aps)
    if not enc_counts:
        log.warning("No encryption data found.")
        return None

    labels = list(enc_counts.keys())
    sizes  = list(enc_counts.values())
    colors = [_ENC_COLORS.get(lbl, _AMB) for lbl in labels]

    fig, ax = plt.subplots(figsize=(6, 6), facecolor=_BG)
    ax.set_facecolor(_BG)

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors,
        autopct="%1.1f%%", startangle=140, pctdistance=0.78,
        wedgeprops={"edgecolor": _BG, "linewidth": 2.5, "width": 0.55},  # donut
    )
    for t in texts:
        t.set_color(_TEXT)
        t.set_fontsize(11)
    for at in autotexts:
        at.set_color(_BG)
        at.set_fontsize(10)
        at.set_fontweight("bold")

    # Centre label
    total = sum(sizes)
    ax.text(0, 0, f"{total}\nAPs", ha="center", va="center",
            color=_TEXT, fontsize=14, fontweight="bold")

    ax.set_title("Encryption Distribution", color=_TEXT, fontsize=13, pad=14)
    plt.tight_layout()

    path = save_path or _default_path(out_dir, "encryption_distribution.png")
    _save(fig, path)
    if show:
        plt.show()
    return path


def plot_client_activity(
    result: ResultLike,
    top_n: int = 15,
    save_path: str | None = None,
    out_dir: str = "reports",
    show: bool = False,
) -> str | None:
    """
    Horizontal bar chart: top-N clients ranked by total frame count.

    Returns the saved file path, or None if skipped.
    """
    if not _require_mpl("plot_client_activity"):
        return None

    clients = _client_list(result)
    if not clients:
        log.warning("No client data found.")
        return None

    top = sorted(clients, key=lambda c: _get(c, "frames", 0), reverse=True)[:top_n]
    macs   = [_get(c, "mac",    "??:??:??:??:??:??") for c in top]
    frames = [_get(c, "frames", 0)                   for c in top]

    fig, ax = plt.subplots(figsize=(9, max(4, 0.4 * len(top))), facecolor=_BG)
    bars = ax.barh(macs, frames, color=_VIO, edgecolor=_MAG, linewidth=0.6, height=0.65)

    _style_ax(ax, title=f"Top {len(top)} Active Clients",
              xlabel="Frame Count", ylabel="MAC Address")
    ax.grid(axis="x", color=_GRID, linewidth=0.6, linestyle="--")
    ax.grid(axis="y", visible=False)
    ax.invert_yaxis()

    for bar, val in zip(bars, frames):
        ax.text(val + max(frames) * 0.01, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", ha="left", color=_TEXT, fontsize=8)

    plt.tight_layout()

    path = save_path or _default_path(out_dir, "client_activity.png")
    _save(fig, path)
    if show:
        plt.show()
    return path


def plot_beacon_timeline(
    result: ResultLike,
    bins: int = 60,
    save_path: str | None = None,
    out_dir: str = "reports",
    show: bool = False,
) -> str | None:
    """
    Stacked area chart: beacon density over time, one colour per AP (top 10).

    Requires `first_seen` / `last_seen` timestamps on each AP.
    Returns the saved file path, or None if skipped.
    """
    if not _require_mpl("plot_beacon_timeline"):
        return None

    aps = _ap_list(result)
    duration = _get(result, "duration", 0.0) or 0.0
    if not aps or duration <= 0:
        log.warning("Insufficient data for beacon timeline.")
        return None

    top_aps = sorted(aps, key=lambda a: _get(a, "beacons", 0), reverse=True)[:10]

    fig, ax = plt.subplots(figsize=(12, 5), facecolor=_BG)
    _style_ax(ax, title="Beacon Rate Over Capture Duration",
              xlabel="Time (s)", ylabel="Estimated Beacons / bin")

    palette = [_CYAN, _VIO, _AMB, _GREEN, _MAG,
               "#FF9E00", "#3A86FF", "#FF006E", "#8338EC", "#FB5607"]

    capture_start = min(
        (_get(a, "first_seen", 0.0) for a in aps), default=0.0
    )

    for ap, color in zip(top_aps, palette):
        fs  = _get(ap, "first_seen", 0.0) - capture_start
        ls  = _get(ap, "last_seen",  0.0) - capture_start
        bcn = _get(ap, "beacons",    0)
        if ls <= fs:
            continue

        # Distribute beacons uniformly across the AP's active window
        bin_edges  = np.linspace(0, duration, bins + 1)
        bin_width  = duration / bins
        rate       = bcn / max(ls - fs, 1.0)   # beacons/s
        counts     = np.array([
            rate * bin_width
            if fs <= (0.5 * (bin_edges[i] + bin_edges[i + 1])) <= ls
            else 0.0
            for i in range(bins)
        ])

        ssid  = _get(ap, "ssid", "?")[:20]
        bssid = _get(ap, "bssid", "")[-5:]  # last 5 chars for brevity
        ax.fill_between(
            bin_edges[:-1], counts,
            alpha=0.55, color=color, linewidth=0,
            label=f"{ssid} ({bssid})",
        )
        ax.plot(bin_edges[:-1], counts, color=color, linewidth=0.8, alpha=0.9)

    ax.legend(
        fontsize=7, framealpha=0.3, facecolor=_BG2, edgecolor=_GRID,
        labelcolor=_TEXT, loc="upper right",
    )
    plt.tight_layout()

    path = save_path or _default_path(out_dir, "beacon_timeline.png")
    _save(fig, path)
    if show:
        plt.show()
    return path


def plot_dashboard(
    result: ResultLike,
    save_path: str | None = None,
    out_dir: str = "reports",
    show: bool = False,
) -> str | None:
    """
    Combined 2×2 dashboard: channel utilisation, encryption pie,
    client activity, beacon timeline — all in a single figure.

    Returns the saved file path, or None if skipped.
    """
    if not _require_mpl("plot_dashboard"):
        return None

    aps     = _ap_list(result)
    clients = _client_list(result)
    fname   = Path(_get(result, "file", "capture")).stem

    fig = plt.figure(figsize=(18, 12), facecolor=_BG)
    fig.suptitle(
        f"PCAP Dashboard — {fname}  "
        f"({len(aps)} APs · {len(clients)} clients · "
        f"{_get(result, 'duration', 0):.1f}s)",
        color=_TEXT, fontsize=15, y=0.98,
    )

    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.38, wspace=0.32)

    # ── top-left: channel utilisation ────────────────────────────────────────
    ax_ch = fig.add_subplot(gs[0, 0])
    channels = [_get(ap, "channel") for ap in aps if _get(ap, "channel") is not None]
    if channels:
        counts = Counter(channels)
        chs    = sorted(counts)
        colors = [_AMB if ch > 14 else _CYAN for ch in chs]
        bars   = ax_ch.bar(chs, [counts[c] for c in chs],
                           color=colors, edgecolor=_VIO, linewidth=0.6, width=0.7)
        _style_ax(ax_ch, "Channel Utilisation", "Channel", "APs")
        ax_ch.xaxis.set_major_locator(mticker.MultipleLocator(max(1, len(chs) // 10)))
        _bar_labels(ax_ch, bars)
    else:
        ax_ch.text(0.5, 0.5, "No channel data", ha="center", va="center",
                   color=_DIM, transform=ax_ch.transAxes)
        _style_ax(ax_ch, "Channel Utilisation")

    # ── top-right: encryption donut ───────────────────────────────────────────
    ax_enc = fig.add_subplot(gs[0, 1])
    enc_counts = Counter(_get(ap, "enc", "UNKNOWN") for ap in aps)
    if enc_counts:
        labels  = list(enc_counts.keys())
        sizes   = list(enc_counts.values())
        colors2 = [_ENC_COLORS.get(l, _AMB) for l in labels]
        wedges, _, autotexts = ax_enc.pie(
            sizes, labels=labels, colors=colors2,
            autopct="%1.0f%%", startangle=140, pctdistance=0.75,
            wedgeprops={"edgecolor": _BG, "linewidth": 2, "width": 0.55},
        )
        for t in wedges:
            pass
        for at in autotexts:
            at.set_color(_BG); at.set_fontsize(9); at.set_fontweight("bold")
        ax_enc.text(0, 0, f"{sum(sizes)}\nAPs", ha="center", va="center",
                    color=_TEXT, fontsize=11, fontweight="bold")
        ax_enc.set_facecolor(_BG)
        ax_enc.set_title("Encryption Distribution", color=_TEXT, fontsize=11, pad=8)
    else:
        ax_enc.text(0.5, 0.5, "No encryption data", ha="center", va="center",
                    color=_DIM, transform=ax_enc.transAxes)
        _style_ax(ax_enc, "Encryption Distribution")

    # ── bottom-left: client activity ──────────────────────────────────────────
    ax_cli = fig.add_subplot(gs[1, 0])
    top_clients = sorted(clients, key=lambda c: _get(c, "frames", 0), reverse=True)[:10]
    if top_clients:
        macs   = [_get(c, "mac", "?") for c in top_clients]
        frames = [_get(c, "frames", 0) for c in top_clients]
        bars2  = ax_cli.barh(macs, frames, color=_VIO, edgecolor=_MAG,
                             linewidth=0.5, height=0.6)
        _style_ax(ax_cli, "Top 10 Active Clients", "Frame Count", "")
        ax_cli.grid(axis="x", color=_GRID, linewidth=0.6, linestyle="--")
        ax_cli.grid(axis="y", visible=False)
        ax_cli.invert_yaxis()
        for bar, val in zip(bars2, frames):
            ax_cli.text(val + max(frames) * 0.01,
                        bar.get_y() + bar.get_height() / 2,
                        str(val), va="center", ha="left",
                        color=_TEXT, fontsize=7)
    else:
        ax_cli.text(0.5, 0.5, "No client data", ha="center", va="center",
                    color=_DIM, transform=ax_cli.transAxes)
        _style_ax(ax_cli, "Top 10 Active Clients")

    # ── bottom-right: beacon timeline ─────────────────────────────────────────
    ax_tl = fig.add_subplot(gs[1, 1])
    duration = _get(result, "duration", 0.0) or 0.0
    top_aps  = sorted(aps, key=lambda a: _get(a, "beacons", 0), reverse=True)[:8]
    cap_start = min((_get(a, "first_seen", 0.0) for a in aps), default=0.0)
    palette   = [_CYAN, _VIO, _AMB, _GREEN, _MAG,
                 "#FF9E00", "#3A86FF", "#FF006E"]
    bins = 40

    if duration > 0 and top_aps:
        for ap, color in zip(top_aps, palette):
            fs  = _get(ap, "first_seen", 0.0) - cap_start
            ls  = _get(ap, "last_seen",  0.0) - cap_start
            bcn = _get(ap, "beacons",    0)
            if ls <= fs:
                continue
            bin_edges = np.linspace(0, duration, bins + 1)
            bw        = duration / bins
            rate      = bcn / max(ls - fs, 1.0)
            counts_tl = np.array([
                rate * bw
                if fs <= (0.5 * (bin_edges[i] + bin_edges[i + 1])) <= ls
                else 0.0
                for i in range(bins)
            ])
            ssid = _get(ap, "ssid", "?")[:16]
            ax_tl.fill_between(bin_edges[:-1], counts_tl,
                               alpha=0.5, color=color, linewidth=0,
                               label=ssid)
            ax_tl.plot(bin_edges[:-1], counts_tl, color=color,
                       linewidth=0.8, alpha=0.9)
        ax_tl.legend(fontsize=6.5, framealpha=0.3, facecolor=_BG2,
                     edgecolor=_GRID, labelcolor=_TEXT, loc="upper right")
    else:
        ax_tl.text(0.5, 0.5, "Insufficient timeline data", ha="center",
                   va="center", color=_DIM, transform=ax_tl.transAxes)
    _style_ax(ax_tl, "Beacon Rate Over Time", "Time (s)", "Beacons / bin")

    path = save_path or _default_path(out_dir, f"{fname}_dashboard.png")
    _save(fig, path)
    if show:
        plt.show()
    return path


# ── public API ────────────────────────────────────────────────────────────────

def plot_all(
    result: ResultLike,
    out_dir: str = "reports",
    dashboard: bool = True,
    individual: bool = True,
    show: bool = False,
) -> list[str]:
    """
    Generate all available plots and save to *out_dir*.

    Parameters
    ----------
    result:
        AnalysisResult dataclass or legacy dict.
    out_dir:
        Output directory (created if needed).
    dashboard:
        If True, also generate the combined dashboard figure.
    individual:
        If True, generate each plot as a separate file.
    show:
        If True, call plt.show() after each figure (interactive mode).

    Returns
    -------
    list[str]
        Paths of all files written.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    saved: list[str] = []

    if individual:
        for fn in (
            plot_channel_utilization,
            plot_encryption_distribution,
            plot_client_activity,
            plot_beacon_timeline,
        ):
            p = fn(result, out_dir=out_dir, show=show)
            if p:
                saved.append(p)

    if dashboard:
        p = plot_dashboard(result, out_dir=out_dir, show=show)
        if p:
            saved.append(p)

    return saved
