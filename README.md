# ESP32 WiFi Security Research Lab

> Plataforma de investigación en seguridad WiFi basada en el microcontrolador ESP32.
> Captura tramas 802.11 en formato PCAP y las analiza offline con herramientas Python.

![Python](https://img.shields.io/badge/Python-3.10%2B-cyan?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-ESP32-blue?style=flat-square&logo=espressif)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Índice

- [Descripción](#descripción)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso rápido — menú interactivo](#uso-rápido--menú-interactivo)
- [Uso avanzado — CLI](#uso-avanzado--cli)
- [Módulos](#módulos)
  - [pcap\_analyzer.py](#pcap_analyzerpy)
  - [visualizer.py](#visualizerpy)
  - [menu.py](#menupy)
- [Ejemplos de salida](#ejemplos-de-salida)
- [Aviso legal](#aviso-legal)

---

## Descripción

Este laboratorio combina firmware ESP32 para captura pasiva de tráfico 802.11 con un
conjunto de herramientas Python para análisis offline. A partir de un archivo PCAP el
sistema extrae:

- **Puntos de acceso** detectados (BSSID, SSID, canal, cifrado, beacons)
- **Clientes WiFi** activos (MAC, tramas enviadas, tiempo de actividad)
- **Estadísticas por canal** en bandas 2.4 GHz, 5 GHz y 6 GHz
- **Exportación** a CSV y JSON
- **Gráficas** de distribución de canales, cifrado, actividad de clientes y timeline

---

## Estructura del proyecto

```
ESP32-WiFi-Security-Research-Lab/
│
├── analyzer/
│   ├── pcap_analyzer.py   # Parser 802.11: APs, clientes, estadísticas
│   └── visualizer.py      # Gráficas matplotlib (canal, cifrado, clientes, timeline)
│
├── captures/              # Directorio de capturas PCAP (no versionado)
├── reports/               # Salida: CSV, JSON, PNG (no versionado)
│
├── menu.py                # Menú TUI interactivo (punto de entrada recomendado)
├── requirements.txt       # Dependencias Python
└── README.md
```

---

## Requisitos

- Python 3.10 o superior
- ESP32 con firmware de captura (o cualquier archivo `.pcap` / `.pcapng`)
- Sistema operativo: Linux, macOS o Windows

---

## Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/AlvGJ-UGR/ESP32-WiFi-Security-Research-Lab.git
cd ESP32-WiFi-Security-Research-Lab

# 2. (Opcional) Crear entorno virtual
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

# 3. Instalar dependencias
pip install -r requirements.txt
```

Dependencias principales:

| Paquete      | Uso                              |
|-------------|----------------------------------|
| `scapy`     | Parseo de PCAP y tramas 802.11   |
| `pandas`    | Exportación CSV                  |
| `matplotlib`| Generación de gráficas           |
| `numpy`     | Cálculos numéricos               |
| `rich`      | Interfaz de terminal enriquecida |

---

## Uso rápido — menú interactivo

El punto de entrada recomendado es el menú TUI. No requiere argumentos:

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

  1  Analizar captura        Parsea un PCAP y muestra el resumen
  2  Analizar directorio     Procesa todos los PCAPs de una carpeta
  3  Exportar resultados     Exporta a CSV y/o JSON
  4  Generar gráficas        Canal, cifrado, clientes, timeline…
  5  Pipeline completo       Analizar + exportar + graficar en un paso
  6  Ver reportes            Lista los archivos generados en /reports

  7  Comprobar dependencias  Verifica si todos los paquetes están instalados
  8  Instalar dependencias   Ejecuta pip install automáticamente
  9  Acerca del proyecto     Información y créditos
  q  Salir
```

El menú incluye un **selector de capturas interactivo** que lista todos los archivos
`.pcap`/`.pcapng` de la carpeta `captures/` con su tamaño y fecha, y permite introducir
una ruta manualmente si la captura está en otro directorio.

---

## Uso avanzado — CLI

Para usuarios que prefieren la línea de comandos:

```bash
# Analizar un archivo y mostrar resumen
python -m analyzer.pcap_analyzer --file captures/sample.pcap

# Analizar un directorio completo
python -m analyzer.pcap_analyzer --dir captures/

# Exportar a CSV y JSON
python -m analyzer.pcap_analyzer --file captures/sample.pcap --export csv json

# Exportar y generar gráficas
python -m analyzer.pcap_analyzer --file captures/sample.pcap --export csv json --plot

# Especificar directorio de salida
python -m analyzer.pcap_analyzer --file captures/sample.pcap --export json --out-dir mis_reportes/

# Logging detallado
python -m analyzer.pcap_analyzer --file captures/sample.pcap --verbose
```

---

## Módulos

### `pcap_analyzer.py`

Parser offline de capturas 802.11. Lee cualquier archivo PCAP/PCAPNG producido por el
firmware ESP32 (o por Wireshark, tcpdump, etc.) y extrae:

- **AccessPoint** — BSSID, SSID, canal, cifrado (WPA3/WPA2/WPA/OPEN·WEP), conteo de
  beacons, ventana temporal de actividad.
- **Client** — MAC, BSSID de referencia, frames totales, ventana temporal.
- **AnalysisResult** — contenedor tipado con estadísticas por canal y serialización
  a dict / JSON lista para exportar.

Detección de cifrado por elemento RSN (ID 48):
- AKM Suite `00:0F:AC:08` (SAE) → **WPA3**
- RSN presente sin SAE → **WPA2**
- Vendor OUI `00:50:F2:01` → **WPA**
- Sin RSN ni vendor → **OPEN/WEP**

### `visualizer.py`

Gráficas matplotlib con tema oscuro (`#0D0D1A`). Compatible con el dataclass
`AnalysisResult` y con el formato dict heredado.

| Función                        | Descripción                                        |
|-------------------------------|----------------------------------------------------|
| `plot_channel_utilization()`  | Barras por canal, separadas por banda              |
| `plot_encryption_distribution()` | Donut con total de APs en el centro             |
| `plot_client_activity()`      | Barras horizontales, top-N clientes por frames     |
| `plot_beacon_timeline()`      | Área apilada: densidad de beacons a lo largo del tiempo |
| `plot_dashboard()`            | Figura 2×2 con los cuatro plots combinados         |
| `plot_all()`                  | Genera todos los plots anteriores                  |

```python
from analyzer.pcap_analyzer import parse_pcap
from analyzer.visualizer import plot_all

result = parse_pcap("captures/sample.pcap")
plot_all(result, out_dir="reports/")
```

### `menu.py`

Interfaz TUI construida con `rich`. Características:

- Selector de capturas con tabla de archivos (nombre, tamaño, fecha)
- Pipeline completo en un solo paso (analizar → exportar → graficar)
- Verificación e instalación de dependencias desde el propio menú
- Opción para abrir el directorio de reportes con el explorador del sistema

---

## Ejemplos de salida

**Resumen en terminal:**

```
╭─────────────────────── 📡 PCAP Analysis Summary ────────────────────────╮
│  File:             captures/sample.pcap                                  │
│  Total frames:     4 821                                                 │
│  Capture duration: 47.3 s                                                │
│  Access Points:    12                                                    │
│  Client MACs:      38                                                    │
╰──────────────────────────────────────────────────────────────────────────╯

╭─────────────────────────── Access Points (12) ───────────────────────────╮
│  BSSID              SSID              Ch  Encryption  Beacons  Active(s) │
│  AA:BB:CC:DD:EE:01  MiRed             6   WPA2         312      45.1     │
│  AA:BB:CC:DD:EE:02  Vecinos_5G        36  WPA3          98      31.7     │
│  …                                                                        │
╰──────────────────────────────────────────────────────────────────────────╯
```

**Archivos generados en `reports/`:**

```
reports/
├── sample_aps_20250613_142301.csv
├── sample_clients_20250613_142301.csv
├── sample_20250613_142301.json
├── channel_utilization.png
├── encryption_distribution.png
├── client_activity.png
├── beacon_timeline.png
└── sample_dashboard.png
```

---

## Aviso legal

> Este proyecto es de uso **exclusivamente educativo e investigador**.
> Úsalo únicamente en redes y dispositivos de tu propiedad o sobre los que tengas
> autorización explícita por escrito.
> El uso no autorizado de herramientas de análisis de tráfico inalámbrico puede
> vulnerar legislación local e internacional.
> Los autores no se responsabilizan del uso indebido de este software.
