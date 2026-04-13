from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from risk_engine.reporter import (
    create_flask_app,
    export_report,
    rank_targets_from_scans,
    render_terminal_summary,
)
from risk_engine.risk import analyze_scan
from scanner import Scanner


def scan_result_to_dict(scan_result: Any) -> dict[str, Any]:
    return {
        "host": getattr(scan_result, "host", ""),
        "os_name": getattr(scan_result, "os_name", ""),
        "os_accuracy": getattr(scan_result, "os_accuracy", None),
        "ports": [
            {
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service,
                "product": port.product,
                "version": port.version,
                "state": port.state,
                **(port.extra or {}),
            }
            for port in getattr(scan_result, "ports", [])
        ],
        "raw": getattr(scan_result, "raw", {}),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze parsed Nmap scan data or run a live Nmap scan with the local risk engine."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        type=Path,
        help="Path to a JSON file containing a ScanResult-style object.",
    )
    parser.add_argument(
        "--target",
        help="Run a live Nmap scan against this host instead of reading JSON input.",
    )
    parser.add_argument(
        "--scan-output",
        type=Path,
        help="Optional path for the XML scan output when using --target.",
    )
    parser.add_argument(
        "--no-recon",
        action="store_true",
        help="Disable optional recon providers such as reverse DNS, HTTP headers, TLS metadata, and Shodan.",
    )
    parser.add_argument(
        "--no-nse-followup",
        action="store_true",
        help="Disable the recommended NSE follow-up pass after the initial scan phases.",
    )
    parser.add_argument(
        "--dump-scan-json",
        type=Path,
        help="Write the parsed live scan result to JSON for later offline analysis.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the output JSON.",
    )
    parser.add_argument(
        "--render",
        choices=("json", "terminal"),
        default="json",
        help="Choose JSON output or a Rich terminal summary.",
    )
    parser.add_argument(
        "--export-txt",
        type=Path,
        help="Write a text report to this path.",
    )
    parser.add_argument(
        "--export-html",
        type=Path,
        help="Write an HTML report to this path.",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch a Flask dashboard for multi-target input.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Dashboard bind host.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Dashboard bind port.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.target:
        scan_result = Scanner().scan(
            args.target,
            xml_path=args.scan_output,
            run_recon=not args.no_recon,
            run_recommended_scripts=not args.no_nse_followup,
        )
        scan_data: dict[str, Any] | list[dict[str, Any]] | Any = scan_result
        if args.dump_scan_json:
            args.dump_scan_json.write_text(
                json.dumps(scan_result_to_dict(scan_result), indent=2),
                encoding="utf-8",
            )
    elif args.input_file:
        with args.input_file.open("r", encoding="utf-8") as handle:
            scan_data = json.load(handle)
    else:
        parser.error("provide either an input_file or --target")

    if isinstance(scan_data, list):
        reports = rank_targets_from_scans(scan_data)

        if args.dashboard:
            app = create_flask_app(reports)
            app.run(host=args.host, port=args.port, debug=False)
            return 0

        if args.render == "terminal":
            for report in reports:
                render_terminal_summary(report)
        elif args.pretty:
            print(json.dumps(reports, indent=2))
        else:
            print(json.dumps(reports))

        if args.export_txt:
            lines = []
            for index, report in enumerate(reports, start=1):
                lines.append(f"Rank {index}: {report.get('host') or 'unknown'}")
                lines.append(f"Score: {report.get('risk_score', 0)}")
                lines.append(f"Severity: {report.get('overall_severity', 'info')}")
                lines.append("")
            args.export_txt.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")

        if args.export_html:
            rows = []
            for index, report in enumerate(reports, start=1):
                rows.append(
                    f"<tr><td>{index}</td><td>{report.get('host') or 'unknown'}</td><td>{report.get('risk_score', 0)}</td><td>{report.get('overall_severity', 'info').upper()}</td><td>{report.get('open_port_count', 0)}</td></tr>"
                )
            html_output = (
                "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>Subnet Ranking</title>"
                "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:32px;background:#f5f7fb;color:#14213d;}table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;}th,td{padding:12px;border-bottom:1px solid #e5e7eb;text-align:left;}th{background:#edf2fb;}</style>"
                "</head><body><h1>Subnet Ranking</h1><table><thead><tr><th>Rank</th><th>Host</th><th>Risk Score</th><th>Severity</th><th>Open Ports</th></tr></thead><tbody>"
                + "".join(rows)
                + "</tbody></table></body></html>"
            )
            args.export_html.write_text(html_output, encoding="utf-8")

        return 0

    report = analyze_scan(scan_data)

    if args.render == "terminal":
        render_terminal_summary(report)
    elif args.pretty:
        print(json.dumps(report, indent=2))
    else:
        print(json.dumps(report))

    if args.export_txt:
        export_report(report, args.export_txt, format="txt")

    if args.export_html:
        export_report(report, args.export_html, format="html")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
