# Nmap Project

This project has been extended from a simple risk-analysis tool into a cleaner
recon and reporting workflow. It now supports:

- Adaptive multi-pass Nmap scanning
- Follow-up NSE scans based on discovered services
- Optional recon enrichment beyond Nmap
- A separate risk engine and reporting layer
- JSON, TXT, HTML, terminal, and dashboard outputs

## Architecture

The project is now split into clearer responsibilities:

- `main.py`
  CLI entry point for live scans and offline analysis.
- `scanner.py`
  Compatibility facade that re-exports the scanner API.
- `scan_engine/engine.py`
  Orchestrates scan phases, follow-up NSE runs, recon providers, and result metadata.
- `scan_engine/models.py`
  Data models for scan profiles, run history, recon snapshots, and summaries.
- `scan_engine/profiles.py`
  Central place for Nmap profile definitions and thresholds.
- `scan_engine/recon.py`
  Optional recon providers such as reverse DNS, HTTP headers, TLS certificate metadata, and Shodan.
- `risk_engine/models.py`
  Typed scan-result objects.
- `risk_engine/risk.py`
  Risk scoring, CVE matching, and recommended NSE script selection.
- `risk_engine/reporter.py`
  Terminal summaries, HTML/TXT export, ranking, and the Flask dashboard.

## Live Scan Workflow

The scanner now runs in phases instead of firing a single Nmap command:

1. `basic`
   Fast TCP SYN and service detection pass.
2. `deep`
   Triggered when the open-port count crosses the configured threshold.
3. `aggressive`
   Triggered for broader attack surfaces.
4. `scripts`
   Runs recommended NSE scripts against the discovered open ports.
5. `recon`
   Enriches the result with optional non-Nmap intelligence.

The result keeps scan metadata in `raw["scan_engine"]`, including:

- profiles that were run
- exact command history
- recommended NSE scripts
- recon-provider output

## Recon Providers

The current recon hooks are optional and safe to disable:

- Reverse DNS
- HTTP header collection
- TLS certificate metadata
- Shodan host intelligence if `SHODAN_API_KEY` is set

Shodan is optional. If the API key is missing, the provider simply returns no data.

## CLI Usage

Analyze a saved scan file:

```powershell
python main.py .\sample_scan.json --pretty
```

Run a live scan:

```powershell
python main.py --target 192.168.1.10 --pretty
```

Run a live scan and save XML:

```powershell
python main.py --target 192.168.1.10 --scan-output .\scan_outputs\host.xml --pretty
```

Dump the parsed live scan result to JSON for later offline analysis:

```powershell
python main.py --target 192.168.1.10 --dump-scan-json .\scan_outputs\host.json --pretty
```

Disable recon enrichment:

```powershell
python main.py --target 192.168.1.10 --no-recon --pretty
```

Disable the recommended NSE follow-up pass:

```powershell
python main.py --target 192.168.1.10 --no-nse-followup --pretty
```

Render a terminal summary:

```powershell
python main.py --target 192.168.1.10 --render terminal
```

Export reports:

```powershell
python main.py --target 192.168.1.10 --export-txt .\report.txt --export-html .\report.html
```

## Output Improvements

The HTML report has been redesigned to show:

- target overview metrics
- findings
- recommended NSE scripts
- scan workflow history
- recon sources

This makes the result easier to review and easier to extend later.

## Tests

Run the full test suite with:

```powershell
& 'C:\Users\Umesh patil\AppData\Local\Python\bin\python.exe' -m unittest discover -s tests -p "test_*.py"
```

## Extension Gaps

The code is now in a better shape to extend, but these are still the best next upgrades:

- UDP scanning profiles for DNS, SNMP, NTP, and SIP exposure
- Subnet and batch orchestration with concurrency controls
- Persistent caching of recon-provider results
- Additional recon providers such as WHOIS, DNS enumeration, Censys, SecurityTrails, or crt.sh
- Rule-based scan planning per service family instead of only port-count thresholds
- Structured plugin loading for external recon tools
- Separate asset storage for raw XML, parsed JSON, and final reports
- Better frontend/dashboard filtering and host drill-down views

## Notes

- `nmap.exe` is already available on this machine.
- Optional UI features still depend on `rich` and `flask`.
- External recon providers depend on network/API access and local API keys where required.
