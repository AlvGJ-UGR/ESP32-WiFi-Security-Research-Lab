# Contributing

Contributions are welcome. This is a research and learning project so the bar is documentation quality and correctness — not just working code.

---

## Ground rules

1. **Strictly educational** — all contributions must stay within the scope of passive analysis and documented protocol behaviour. Nothing that facilitates or simplifies unauthorized access to networks.
2. **One concern per PR** — keep pull requests focused.
3. **Document what you add** — every new function needs a docstring / Doxygen comment.

---

## Repo layout

| Path | What lives here |
|------|----------------|
| `firmware/` | ESP-IDF C firmware — build with `idf.py` |
| `analyzer/` | Python offline analysis toolkit |
| `docs/` | Protocol references and setup guides |
| `captures/` | **git-ignored** — never commit `.pcap` files |
| `reports/` | **git-ignored** — generated plots and CSVs |

---

## Firmware (ESP-IDF / C)

- Follow the [ESP-IDF coding style](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/contribute/style-guide.html).
- Use Doxygen-style `/** ... */` comments for all public headers.
- New components go in `firmware/components/<name>/` with their own `CMakeLists.txt`.

## Python analyzer

- Follow PEP 8.
- Every public function: NumPy-style docstring with **Parameters** and **Returns**.
- New analysis scripts belong in `analyzer/`, not the repo root.

---

## Submitting a PR

1. Fork and create a branch: `git checkout -b feature/your-topic`
2. Make your changes and confirm `python analyzer/pcap_analyzer.py --help` works.
3. Open a PR with a clear description: what problem it solves, what you changed.

---

## Opening issues

Use the GitHub issue tracker for bugs, questions, and feature requests. Please include:
- ESP-IDF version (for firmware issues): `idf.py --version`
- Python version (for analyzer issues): `python --version`
- Minimal reproducer or error output
