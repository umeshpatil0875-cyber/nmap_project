# Nmap Project

`nmap_project` is a Python-based Nmap workflow that combines live scanning,
optional recon enrichment, risk scoring, and report generation. It is designed
to support both direct scans and offline analysis of saved scan results.

## Features

- Multi-pass scan orchestration for progressively deeper inspection
- Optional follow-up NSE script runs based on discovered services
- Recon enrichment such as reverse DNS, HTTP headers, TLS metadata, and Shodan
- Separate risk-analysis and reporting layers
- JSON, TXT, HTML, terminal, and dashboard-style outputs

## Project Structure

- `main.py`: CLI entry point for live scans and offline analysis
- `scanner.py`: compatibility facade that re-exports the scanner API
- `scan_engine/`: scan orchestration, profiles, recon providers, and models
- `risk_engine/`: parsed result models, risk scoring, and report generation
- `tests/`: unit tests for scanner, reporter, and risk logic

## Scan Workflow

The live scanner works in phases instead of using a single fixed Nmap command:

1. `basic` for fast host and service discovery
2. `deep` when the target exposes a larger attack surface
3. `aggressive` for broader inspection
4. `scripts` for recommended NSE follow-up checks
5. `recon` for optional non-Nmap enrichment

Scan metadata is stored under `raw["scan_engine"]`, including command history,
executed profiles, recommended NSE scripts, and recon provider output.

## Usage

Analyze a saved scan file:

```powershell
python main.py .\sample_scan.json --pretty
```

Run a live scan:

```powershell
python main.py --target 192.168.1.10 --pretty
```

Run a live scan and save XML output:

```powershell
python main.py --target 192.168.1.10 --scan-output .\scan_outputs\host.xml --pretty
```

Dump parsed scan data to JSON for later offline analysis:

```powershell
python main.py --target 192.168.1.10 --dump-scan-json .\scan_outputs\host.json --pretty
```

Disable recon enrichment:

```powershell
python main.py --target 192.168.1.10 --no-recon --pretty
```

Disable recommended NSE follow-up scans:

```powershell
python main.py --target 192.168.1.10 --no-nse-followup --pretty
```

Render a terminal summary:

```powershell
python main.py --target 192.168.1.10 --render terminal
```

Export TXT and HTML reports:

```powershell
python main.py --target 192.168.1.10 --export-txt .\report.txt --export-html .\report.html
```

## Testing

Run the test suite with:

```powershell
& 'C:\Users\Umesh patil\AppData\Local\Python\bin\python.exe' -m unittest discover -s tests -p "test_*.py"
```

## Notes

- `nmap.exe` must be available for live scans
- Shodan enrichment requires `SHODAN_API_KEY`
- Optional UI features depend on `rich` and `flask`
