from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .risk import SEVERITY_ORDER, analyze_scan

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    Console = Any  # type: ignore[assignment]
    HAS_RICH = False


SEVERITY_STYLES = {
    "info": "cyan",
    "low": "green",
    "medium": "yellow",
    "high": "bold red",
    "critical": "bold white on red",
}


def ensure_report(report_or_scan: dict[str, Any]) -> dict[str, Any]:
    if "findings" in report_or_scan and "overall_severity" in report_or_scan:
        return report_or_scan
    return analyze_scan(report_or_scan)


def render_terminal_summary(report_or_scan: dict[str, Any], console: Console | None = None) -> None:
    report = ensure_report(report_or_scan)
    if not HAS_RICH:
        raise RuntimeError("Rich is not installed. Run: pip install rich")

    console = console or Console()
    severity = report["overall_severity"]
    style = SEVERITY_STYLES.get(severity, "white")

    console.print(
        Panel.fit(
            f"[bold]Host:[/bold] {report.get('host') or 'unknown'}\n"
            f"[bold]OS:[/bold] {report.get('os_name') or 'unknown'}\n"
            f"[bold]Open ports:[/bold] {report.get('open_port_count', 0)}\n"
            f"[bold]Risk score:[/bold] {report.get('risk_score', 0)}\n"
            f"[bold]Overall:[/bold] [{style}]{severity.upper()}[/{style}]",
            title="Risk Summary",
            border_style=style,
        )
    )

    findings_table = Table(title="Findings")
    findings_table.add_column("Severity", style="bold")
    findings_table.add_column("Title")
    findings_table.add_column("Port")
    findings_table.add_column("Rationale")
    for finding in sorted(
        report.get("findings", []),
        key=lambda item: SEVERITY_ORDER[item["severity"]],
        reverse=True,
    ):
        finding_style = SEVERITY_STYLES.get(finding["severity"], "white")
        findings_table.add_row(
            f"[{finding_style}]{finding['severity'].upper()}[/{finding_style}]",
            finding["title"],
            str(finding.get("port") or "-"),
            finding["rationale"],
        )
    console.print(findings_table)

    scripts = report.get("recommended_nse_scripts", [])
    if scripts:
        scripts_table = Table(title="Recommended NSE Scripts")
        scripts_table.add_column("Script")
        for script in scripts:
            scripts_table.add_row(script)
        console.print(scripts_table)


def report_to_text(report_or_scan: dict[str, Any]) -> str:
    report = ensure_report(report_or_scan)
    scan_engine = report.get("raw", {}).get("scan_engine", {})
    lines = [
        f"Host: {report.get('host') or 'unknown'}",
        f"OS: {report.get('os_name') or 'unknown'}",
        f"Open ports: {report.get('open_port_count', 0)}",
        f"Risk score: {report.get('risk_score', 0)}",
        f"Overall severity: {report.get('overall_severity', 'info')}",
        "",
        "Findings:",
    ]

    for finding in sorted(
        report.get("findings", []),
        key=lambda item: SEVERITY_ORDER[item["severity"]],
        reverse=True,
    ):
        port_text = f" port {finding['port']}" if finding.get("port") else ""
        lines.append(f"- [{finding['severity'].upper()}] {finding['title']}{port_text}")
        lines.append(f"  {finding['rationale']}")

    scripts = report.get("recommended_nse_scripts", [])
    if scripts:
        lines.extend(["", "Recommended NSE scripts:"])
        lines.extend(f"- {script}" for script in scripts)

    if scan_engine.get("profiles"):
        lines.extend(["", "Scan workflow:"])
        lines.append(f"- Profiles run: {', '.join(scan_engine['profiles'])}")
        if scan_engine.get("recon"):
            lines.append(
                "- Recon sources: "
                + ", ".join(item["provider"] for item in scan_engine["recon"])
            )

    return "\n".join(lines)


def report_to_html(report_or_scan: dict[str, Any]) -> str:
    report = ensure_report(report_or_scan)
    finding_items = "\n".join(
        (
            "<tr>"
            f"<td class='sev {html.escape(item['severity'])}'>{html.escape(item['severity'].upper())}</td>"
            f"<td>{html.escape(item['title'])}</td>"
            f"<td>{html.escape(str(item.get('port') or '-'))}</td>"
            f"<td>{html.escape(item['rationale'])}</td>"
            "</tr>"
        )
        for item in sorted(
            report.get("findings", []),
            key=lambda entry: SEVERITY_ORDER[entry["severity"]],
            reverse=True,
        )
    )
    script_items = "\n".join(
        f"<li>{html.escape(script)}</li>" for script in report.get("recommended_nse_scripts", [])
    )

    scan_engine = report.get("raw", {}).get("scan_engine", {})
    workflow_items = "".join(
        f"<li><strong>{html.escape(run['profile'])}</strong> | open ports seen: {run.get('open_port_count', 0)}</li>"
        for run in scan_engine.get("run_history", [])
    )
    recon_items = "".join(
        f"<li><strong>{html.escape(item['provider'])}</strong> - {html.escape(item['summary'])}</li>"
        for item in scan_engine.get("recon", [])
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Risk Report - {html.escape(report.get("host") or "unknown")}</title>
  <style>
    :root {{ color-scheme: light; --ink:#0f172a; --muted:#475569; --paper:#fffdf8; --panel:#fff; --line:#e2e8f0; --accent:#0f766e; --accent-2:#b45309; --shadow:0 20px 40px rgba(15,23,42,0.08); }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: radial-gradient(circle at top left, #fef3c7 0, #fff7ed 32%, #f8fafc 100%); color: var(--ink); }}
    .page {{ max-width: 1120px; margin: 0 auto; padding: 32px; }}
    .hero {{ background: linear-gradient(135deg, rgba(15,118,110,0.95), rgba(180,83,9,0.9)); color: white; border-radius: 28px; padding: 28px; margin-bottom: 24px; box-shadow: var(--shadow); }}
    .card {{ background: var(--panel); border-radius: 22px; padding: 24px; box-shadow: var(--shadow); margin-bottom: 24px; border: 1px solid rgba(255,255,255,0.5); }}
    .headline {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }}
    .metric {{ min-width: 180px; }}
    .metric strong {{ display:block; font-size: 0.8rem; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 8px; opacity: 0.8; }}
    .metric-value {{ font-size: 1.25rem; font-weight: 700; }}
    .critical {{ color: #9b2226; font-weight: 700; }}
    .high {{ color: #bb3e03; font-weight: 700; }}
    .medium {{ color: #ca6702; font-weight: 700; }}
    .low {{ color: #2a9d8f; font-weight: 700; }}
    .info {{ color: #277da1; font-weight: 700; }}
    h1, h2, h3 {{ margin-top: 0; }}
    .subtle {{ color: var(--muted); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    th {{ background: #f8fafc; }}
    ul {{ margin: 0; padding-left: 20px; }}
    .grid {{ display: grid; gap: 24px; grid-template-columns: 2fr 1fr; }}
    @media (max-width: 880px) {{ .grid {{ grid-template-columns: 1fr; }} .page {{ padding: 20px; }} }}
  </style>
</head>
<body>
  <div class="page">
  <div class="hero">
    <h1>Target Risk Report</h1>
    <p class="subtle" style="color:rgba(255,255,255,0.85);">Adaptive scan workflow, risk findings, and recon enrichment in one report.</p>
  </div>
  <div class="card">
    <div class="headline">
      <div class="metric"><strong>Host</strong><div class="metric-value">{html.escape(report.get("host") or "unknown")}</div></div>
      <div class="metric"><strong>OS</strong><div class="metric-value">{html.escape(report.get("os_name") or "unknown")}</div></div>
      <div class="metric"><strong>Open ports</strong><div class="metric-value">{report.get("open_port_count", 0)}</div></div>
      <div class="metric"><strong>Risk score</strong><div class="metric-value">{report.get("risk_score", 0)}</div></div>
      <div class="metric"><strong>Overall severity</strong><div class="metric-value"><span class="{html.escape(report.get("overall_severity", "info"))}">{html.escape(report.get("overall_severity", "info").upper())}</span></div></div>
    </div>
  </div>
  <div class="grid">
  <div>
  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Title</th><th>Port</th><th>Rationale</th></tr>
      </thead>
      <tbody>
        {finding_items}
      </tbody>
    </table>
  </div>
  </div>
  <div>
  <div class="card">
    <h2>Recommended NSE Scripts</h2>
    <ul>
      {script_items or '<li>None</li>'}
    </ul>
  </div>
  <div class="card">
    <h2>Scan Workflow</h2>
    <ul>
      {workflow_items or '<li>No workflow metadata captured.</li>'}
    </ul>
  </div>
  <div class="card">
    <h2>Recon Sources</h2>
    <ul>
      {recon_items or '<li>No recon enrichment collected.</li>'}
    </ul>
  </div>
  </div>
  </div>
  </div>
</body>
</html>
"""


def export_report(report_or_scan: dict[str, Any], output_path: str | Path, format: str | None = None) -> Path:
    report = ensure_report(report_or_scan)
    output = Path(output_path)
    export_format = (format or output.suffix.lstrip(".")).lower()

    if export_format == "txt":
        output.write_text(report_to_text(report), encoding="utf-8")
    elif export_format == "html":
        output.write_text(report_to_html(report), encoding="utf-8")
    elif export_format == "json":
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        raise ValueError(f"Unsupported export format: {export_format}")
    return output


def rank_reports(reports_or_scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reports = [ensure_report(item) for item in reports_or_scans]
    return sorted(
        reports,
        key=lambda report: (
            report.get("risk_score", 0),
            SEVERITY_ORDER.get(report.get("overall_severity", "info"), 0),
            report.get("open_port_count", 0),
        ),
        reverse=True,
    )


def rank_targets_from_scans(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return rank_reports([analyze_scan(scan) for scan in scans])


def create_flask_app(reports_or_scans: list[dict[str, Any]]):
    try:
        from flask import Flask, render_template_string
    except ImportError as exc:
        raise RuntimeError("Flask is not installed. Run: pip install flask") from exc

    reports = rank_reports(reports_or_scans)
    template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Nmap Risk Dashboard</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; background: #f7f7f2; color: #222; margin: 24px; }
    .card { background: white; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 8px 20px rgba(0,0,0,0.08); }
    .critical { border-left: 8px solid #9b2226; }
    .high { border-left: 8px solid #bb3e03; }
    .medium { border-left: 8px solid #ca6702; }
    .low { border-left: 8px solid #2a9d8f; }
    .info { border-left: 8px solid #277da1; }
  </style>
</head>
<body>
  <h1>Nmap Risk Dashboard</h1>
  {% for report in reports %}
    <div class="card {{ report.overall_severity }}">
      <h2>{{ report.host or 'unknown' }} | score {{ report.risk_score }} | {{ report.overall_severity.upper() }}</h2>
      <p><strong>OS:</strong> {{ report.os_name or 'unknown' }} | <strong>Open ports:</strong> {{ report.open_port_count }}</p>
      <ul>
        {% for finding in report.findings[:5] %}
          <li>[{{ finding.severity.upper() }}] {{ finding.title }}</li>
        {% endfor %}
      </ul>
    </div>
  {% endfor %}
</body>
</html>
"""

    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template_string(template, reports=reports)

    return app
