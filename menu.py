"""
menu.py  –  ESP32 WiFi Security Research Lab
=============================================
Interactive terminal menu.  No arguments needed — just run:

    python menu.py

Requirements (same as the rest of the project):
    pip install rich scapy pandas matplotlib
"""

from __future__ import annotations

import os
import sys
import time
import shutil
import subprocess
from pathlib import Path
from datetime import datetime

# ── rich ──────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.columns import Columns
    from rich.text import Text
    from rich.rule import Rule
    from rich.live import Live
    from rich.spinner import Spinner
    from rich import box
    from rich.padding import Padding
    from rich.align import Align
except ImportError:
    print("[ERROR] rich not installed.  Run: pip install rich")
    sys.exit(1)

console = Console()

# ── paths ─────────────────────────────────────────────────────────────────────
ROOT         = Path(__file__).parent
CAPTURES_DIR = ROOT / "captures"
REPORTS_DIR  = ROOT / "reports"
ANALYZER_MOD = ROOT / "analyzer" / "pcap_analyzer.py"
VISUALIZER_MOD = ROOT / "analyzer" / "visualizer.py"

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

# ── colour palette (matches visualizer.py) ────────────────────────────────────
C_CYAN  = "cyan"
C_VIO   = "bright_magenta"
C_MAG   = "magenta"
C_AMB   = "yellow"
C_GREEN = "bright_green"
C_DIM   = "dim"
C_ERR   = "red"
C_OK    = "bright_green"

# ── helpers ───────────────────────────────────────────────────────────────────

def _banner() -> None:
    console.clear()
    banner = Text(justify="center")
    banner.append("  ███████╗███████╗██████╗ ██████╗ ██████╗  \n", style="bold cyan")
    banner.append("  ██╔════╝██╔════╝██╔══██╗╚════██╗╚════██╗ \n", style="bold cyan")
    banner.append("  █████╗  ███████╗██████╔╝ █████╔╝ █████╔╝ \n", style="bold bright_magenta")
    banner.append("  ██╔══╝  ╚════██║██╔═══╝ ██╔═══╝  ╚═══██╗ \n", style="bold bright_magenta")
    banner.append("  ███████╗███████║██║      ███████╗██████╔╝ \n", style="bold magenta")
    banner.append("  ╚══════╝╚══════╝╚═╝      ╚══════╝╚═════╝  \n", style="bold magenta")
    console.print(Align.center(banner))
    console.print(Align.center(
        Text("WiFi Security Research Lab  ·  ESP32 Edition", style="bold dim")
    ))
    console.print(Rule(style="dim"))


def _ok(msg: str) -> None:
    console.print(f"  [bold {C_OK}]✔[/]  {msg}")


def _warn(msg: str) -> None:
    console.print(f"  [bold {C_AMB}]![/]  [yellow]{msg}[/]")


def _err(msg: str) -> None:
    console.print(f"  [bold {C_ERR}]✘[/]  [red]{msg}[/]")


def _pause() -> None:
    console.print()
    Prompt.ask("  [dim]Pulsa Enter para continuar[/]", default="")


def _section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold cyan] {title} [/]", style="cyan"))
    console.print()


def _spinner(msg: str) -> "Live":
    return Live(
        Spinner("dots", text=f"[cyan]{msg}[/]", style="cyan"),
        console=console,
        refresh_per_second=15,
        transient=True,
    )


def _check_dep(module: str) -> bool:
    """Return True if *module* is importable."""
    import importlib.util
    return importlib.util.find_spec(module) is not None


def _dep_badge(name: str, module: str) -> Text:
    ok = _check_dep(module)
    t  = Text()
    t.append(f"  {'✔' if ok else '✘'}  {name}", style=C_OK if ok else C_ERR)
    return t

# ── PCAP file picker ──────────────────────────────────────────────────────────

def _list_captures(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in PCAP_EXTS
    )


def pick_capture(prompt_label: str = "Selecciona una captura") -> Path | None:
    """Interactive file picker.  Returns the chosen Path or None."""
    files = _list_captures(CAPTURES_DIR)

    if not files:
        _warn(f"No se encontraron capturas en [cyan]{CAPTURES_DIR}[/]")
        manual = Confirm.ask("  ¿Introducir ruta manualmente?", default=True)
        if not manual:
            return None
        raw = Prompt.ask("  Ruta al archivo PCAP").strip()
        p = Path(raw)
        if not p.is_file():
            _err(f"Archivo no encontrado: {raw}")
            return None
        return p

    table = Table(box=box.SIMPLE, show_header=True, border_style="dim")
    table.add_column("#",       style="bold cyan",  width=4)
    table.add_column("Archivo", style="white",      min_width=30)
    table.add_column("Tamaño",  style="dim",        justify="right")
    table.add_column("Fecha",   style="dim")

    for i, f in enumerate(files, 1):
        stat = f.stat()
        size = f"{stat.st_size / 1024:.1f} KB" if stat.st_size < 1_048_576 \
               else f"{stat.st_size / 1_048_576:.2f} MB"
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M")
        table.add_row(str(i), f.name, size, mtime)

    table.add_row("0", "[dim]Introducir ruta manualmente[/]", "", "")
    console.print(table)

    choice = IntPrompt.ask(
        f"  [cyan]{prompt_label}[/] [dim](0-{len(files)})[/]",
        default=1,
    )

    if choice == 0:
        raw = Prompt.ask("  Ruta al archivo PCAP").strip()
        p   = Path(raw)
        if not p.is_file():
            _err(f"Archivo no encontrado: {raw}")
            return None
        return p
    if 1 <= choice <= len(files):
        return files[choice - 1]
    _err("Opción fuera de rango.")
    return None

# ── lazy imports (only when actually needed) ──────────────────────────────────

def _load_analyzer():
    """Import pcap_analyzer without crashing the menu if scapy is missing."""
    try:
        # support both installed package and sibling directory
        sys.path.insert(0, str(ROOT))
        from analyzer import pcap_analyzer as pa
        return pa
    except ImportError as exc:
        _err(f"No se pudo importar pcap_analyzer: {exc}")
        return None


def _load_visualizer():
    try:
        sys.path.insert(0, str(ROOT))
        from analyzer import visualizer as viz
        return viz
    except ImportError as exc:
        _err(f"No se pudo importar visualizer: {exc}")
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  ACCIONES
# ══════════════════════════════════════════════════════════════════════════════

def action_analyze() -> None:
    """Analizar un archivo PCAP y mostrar el resumen."""
    _section("Analizar captura PCAP")
    target = pick_capture()
    if target is None:
        return

    pa = _load_analyzer()
    if pa is None:
        return

    with _spinner(f"Analizando {target.name} …"):
        try:
            result = pa.parse_pcap(target)
        except Exception as exc:
            _err(f"Error al parsear: {exc}")
            return

    pa.print_summary(result)
    _pause()


def action_analyze_dir() -> None:
    """Analizar todos los PCAPs de un directorio."""
    _section("Analizar directorio de capturas")

    raw = Prompt.ask(
        "  Directorio con capturas",
        default=str(CAPTURES_DIR),
    ).strip()
    d = Path(raw)
    if not d.is_dir():
        _err(f"Directorio no encontrado: {d}")
        return

    pa = _load_analyzer()
    if pa is None:
        return

    results = pa.parse_directory(d)
    if not results:
        _warn("No se encontraron capturas en ese directorio.")
        return

    for result in results:
        console.print(Rule(style="dim"))
        pa.print_summary(result)

    _ok(f"Procesados {len(results)} archivo(s).")
    _pause()


def action_export() -> None:
    """Exportar resultados a CSV y/o JSON."""
    _section("Exportar resultados")
    target = pick_capture()
    if target is None:
        return

    pa = _load_analyzer()
    if pa is None:
        return

    # Choose formats
    fmt_table = Table(box=box.SIMPLE, show_header=False, border_style="dim")
    fmt_table.add_column("", style="cyan", width=4)
    fmt_table.add_column("", style="white")
    fmt_table.add_row("1", "CSV  (APs + Clients en tablas separadas)")
    fmt_table.add_row("2", "JSON (resultado completo)")
    fmt_table.add_row("3", "CSV + JSON")
    console.print(fmt_table)
    fmt_choice = IntPrompt.ask("  Formato de exportación", default=3)

    out = Prompt.ask("  Directorio de salida", default=str(REPORTS_DIR)).strip()

    with _spinner("Parseando captura …"):
        try:
            result = pa.parse_pcap(target)
        except Exception as exc:
            _err(f"Error al parsear: {exc}")
            return

    if fmt_choice in (1, 3):
        pa.export_csv(result, out)
    if fmt_choice in (2, 3):
        pa.export_json(result, out)

    _ok(f"Exportación completada → [cyan]{out}[/]")
    _pause()


def action_plot() -> None:
    """Generar gráficas a partir de una captura."""
    _section("Generar gráficas")

    if not _check_dep("matplotlib"):
        _err("matplotlib no está instalado.")
        console.print("  Instálalo con: [bold cyan]pip install matplotlib[/]")
        _pause()
        return

    target = pick_capture()
    if target is None:
        return

    pa  = _load_analyzer()
    viz = _load_visualizer()
    if pa is None or viz is None:
        return

    # Which plots?
    plot_table = Table(box=box.SIMPLE, show_header=False, border_style="dim")
    plot_table.add_column("", style="cyan", width=4)
    plot_table.add_column("", style="white")
    plot_table.add_row("1", "Canal WiFi (2.4 GHz / 5 GHz / 6 GHz)")
    plot_table.add_row("2", "Distribución de cifrado (donut)")
    plot_table.add_row("3", "Actividad de clientes (top-N)")
    plot_table.add_row("4", "Timeline de beacons")
    plot_table.add_row("5", "Dashboard completo (2×2)")
    plot_table.add_row("6", "Todos los anteriores")
    console.print(plot_table)
    plot_choice = IntPrompt.ask("  Gráfica a generar", default=5)

    out = Prompt.ask("  Directorio de salida", default=str(REPORTS_DIR)).strip()
    Path(out).mkdir(parents=True, exist_ok=True)

    with _spinner("Parseando captura …"):
        try:
            result = pa.parse_pcap(target)
        except Exception as exc:
            _err(f"Error al parsear: {exc}")
            return

    dispatch = {
        1: lambda: viz.plot_channel_utilization(result, out_dir=out),
        2: lambda: viz.plot_encryption_distribution(result, out_dir=out),
        3: lambda: viz.plot_client_activity(result, out_dir=out),
        4: lambda: viz.plot_beacon_timeline(result, out_dir=out),
        5: lambda: viz.plot_dashboard(result, out_dir=out),
        6: lambda: viz.plot_all(result, out_dir=out),
    }

    fn = dispatch.get(plot_choice)
    if fn is None:
        _err("Opción no válida.")
        return

    with _spinner("Generando gráficas …"):
        try:
            fn()
        except Exception as exc:
            _err(f"Error al generar gráfica: {exc}")
            return

    _ok(f"Gráficas guardadas en [cyan]{out}[/]")

    # offer to open the reports folder
    if Confirm.ask("  ¿Abrir directorio de reportes?", default=False):
        _open_folder(out)

    _pause()


def action_full_pipeline() -> None:
    """Analizar + exportar CSV/JSON + generar todas las gráficas en un solo paso."""
    _section("Pipeline completo (analizar → exportar → graficar)")
    target = pick_capture()
    if target is None:
        return

    out = Prompt.ask("  Directorio de salida", default=str(REPORTS_DIR)).strip()
    Path(out).mkdir(parents=True, exist_ok=True)

    pa  = _load_analyzer()
    viz = _load_visualizer()
    if pa is None:
        return

    with _spinner(f"Analizando {target.name} …"):
        try:
            result = pa.parse_pcap(target)
        except Exception as exc:
            _err(f"Error al parsear: {exc}")
            return

    pa.print_summary(result)

    console.print()
    _ok("Exportando CSV + JSON …")
    pa.export_csv(result, out)
    pa.export_json(result, out)

    if viz and _check_dep("matplotlib"):
        _ok("Generando todas las gráficas …")
        with _spinner("Renderizando …"):
            try:
                viz.plot_all(result, out_dir=out)
            except Exception as exc:
                _warn(f"Error en gráficas: {exc}")
    else:
        _warn("matplotlib no disponible — se omiten las gráficas.")

    console.print()
    _ok(f"Pipeline completado.  Resultados en [cyan]{out}[/]")

    if Confirm.ask("  ¿Abrir directorio de reportes?", default=False):
        _open_folder(out)

    _pause()


def action_list_reports() -> None:
    """Mostrar los reportes generados en el directorio de salida."""
    _section("Reportes generados")

    out = Path(Prompt.ask("  Directorio de reportes", default=str(REPORTS_DIR)).strip())
    if not out.exists():
        _warn("El directorio de reportes no existe todavía.")
        _pause()
        return

    files = sorted(out.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files:
        _warn("No hay reportes en ese directorio.")
        _pause()
        return

    table = Table(box=box.SIMPLE, border_style="dim", show_header=True)
    table.add_column("Archivo",  style="white", min_width=30)
    table.add_column("Tipo",     style="cyan",  width=6)
    table.add_column("Tamaño",   style="dim",   justify="right")
    table.add_column("Generado", style="dim")

    for f in files:
        if not f.is_file():
            continue
        stat  = f.stat()
        size  = f"{stat.st_size / 1024:.1f} KB"
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M")
        ext   = f.suffix.upper().lstrip(".")
        table.add_row(f.name, ext, size, mtime)

    console.print(table)

    if Confirm.ask("  ¿Abrir directorio?", default=False):
        _open_folder(str(out))

    _pause()


def action_check_deps() -> None:
    """Comprobar el estado de las dependencias."""
    _section("Estado de dependencias")

    deps = [
        ("scapy",      "scapy",      "Parseo de PCAP / 802.11"),
        ("pandas",     "pandas",     "Exportación CSV"),
        ("matplotlib", "matplotlib", "Generación de gráficas"),
        ("numpy",      "numpy",      "Cálculos numéricos (gráficas)"),
        ("rich",       "rich",       "Interfaz de terminal"),
    ]

    table = Table(box=box.ROUNDED, border_style="dim", show_header=True)
    table.add_column("Paquete",      style="white",  min_width=14)
    table.add_column("Estado",       style="white",  width=10)
    table.add_column("Descripción",  style="dim")

    all_ok = True
    for pkg, mod, desc in deps:
        ok = _check_dep(mod)
        if not ok:
            all_ok = False
        status = Text("✔  OK",      style=C_OK)  if ok \
            else Text("✘  Falta",   style=C_ERR)
        table.add_row(pkg, status, desc)

    console.print(table)

    if not all_ok:
        console.print()
        _warn("Instala los paquetes que faltan con:")
        console.print("   [bold cyan]pip install -r requirements.txt[/]")

    _pause()


def action_install_deps() -> None:
    """Instalar todas las dependencias automáticamente."""
    _section("Instalar dependencias")

    req_file = ROOT / "requirements.txt"
    if req_file.exists():
        console.print(f"  Usando [cyan]{req_file}[/]")
        cmd = [sys.executable, "-m", "pip", "install", "-r", str(req_file)]
    else:
        pkgs = ["scapy", "pandas", "matplotlib", "numpy", "rich"]
        _warn(f"requirements.txt no encontrado.  Instalando: {', '.join(pkgs)}")
        cmd = [sys.executable, "-m", "pip", "install"] + pkgs

    console.print()
    try:
        subprocess.run(cmd, check=True)
        console.print()
        _ok("Instalación completada.")
    except subprocess.CalledProcessError as exc:
        _err(f"pip falló (código {exc.returncode}).")

    _pause()


def action_about() -> None:
    """Mostrar información del proyecto."""
    _section("Acerca del proyecto")

    console.print(Panel(
        "[bold cyan]ESP32 WiFi Security Research Lab[/]\n\n"
        "Herramienta de investigación en seguridad WiFi basada en el\n"
        "microcontrolador ESP32.  Captura tramas 802.11, las almacena\n"
        "en formato PCAP y permite analizarlas offline.\n\n"
        "[dim]Módulos:[/]\n"
        "  • [cyan]analyzer/pcap_analyzer.py[/]  — parser 802.11\n"
        "  • [cyan]analyzer/visualizer.py[/]      — gráficas matplotlib\n"
        "  • [cyan]menu.py[/]                      — esta interfaz\n\n"
        "[dim]Repositorio:[/] github.com/AlvGJ-UGR/ESP32-WiFi-Security-Research-Lab\n\n"
        "[bold yellow]⚠  Uso exclusivamente educativo y en redes propias.[/]",
        border_style="cyan",
        title="ℹ  Info",
    ))
    _pause()


# ── helper: open folder in OS file manager ────────────────────────────────────

def _open_folder(path: str) -> None:
    import platform
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(path)        # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as exc:
        _warn(f"No se pudo abrir el explorador: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
#  MENÚ PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

MENU_ITEMS: list[tuple[str, str, str, object]] = [
    # key, label, description, action
    ("1", "Analizar captura",           "Parsea un PCAP y muestra el resumen",              action_analyze),
    ("2", "Analizar directorio",        "Procesa todos los PCAPs de una carpeta",            action_analyze_dir),
    ("3", "Exportar resultados",        "Exporta a CSV y/o JSON",                            action_export),
    ("4", "Generar gráficas",           "Canal, cifrado, clientes, timeline…",               action_plot),
    ("5", "Pipeline completo",          "Analizar + exportar + graficar en un paso",         action_full_pipeline),
    ("6", "Ver reportes",               "Lista los archivos generados en /reports",          action_list_reports),
    ("─", "──────────────────────────", "──────────────────────────────────────────────",    None),
    ("7", "Comprobar dependencias",     "Verifica si todos los paquetes están instalados",   action_check_deps),
    ("8", "Instalar dependencias",      "Ejecuta pip install automáticamente",               action_install_deps),
    ("9", "Acerca del proyecto",        "Información y créditos",                            action_about),
    ("q", "Salir",                      "",                                                  None),
]


def _draw_menu() -> None:
    _banner()
    console.print()

    table = Table(
        box=box.SIMPLE,
        show_header=False,
        border_style="dim",
        padding=(0, 1),
        expand=False,
    )
    table.add_column("key",  style="bold cyan",  width=4,  no_wrap=True)
    table.add_column("name", style="white",       min_width=26)
    table.add_column("desc", style="dim",         min_width=44)

    for key, label, desc, _ in MENU_ITEMS:
        if key == "─":
            table.add_row("", "", "")
        elif key == "q":
            table.add_row(f"[red]{key}[/]", f"[red]{label}[/]", desc)
        else:
            table.add_row(f"[bold cyan]{key}[/]", label, desc)

    console.print(Padding(table, (0, 4)))
    console.print()


def _valid_keys() -> set[str]:
    return {k.lower() for k, *_ in MENU_ITEMS if k not in ("─",)}


def main() -> None:
    valid = _valid_keys()
    action_map = {k.lower(): fn for k, _, _, fn in MENU_ITEMS if k not in ("─",) and fn}

    while True:
        _draw_menu()
        raw = Prompt.ask(
            "  [bold cyan]Opción[/]",
            default="1",
        ).strip().lower()

        if raw not in valid:
            _err("Opción no reconocida.")
            time.sleep(0.8)
            continue

        if raw == "q":
            console.print()
            console.print(Align.center(
                Text("¡Hasta luego! 👋", style="bold cyan")
            ))
            console.print()
            sys.exit(0)

        fn = action_map.get(raw)
        if fn:
            fn()


if __name__ == "__main__":
    main()
