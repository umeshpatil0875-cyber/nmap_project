from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import PortInfo, ScanResult


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SERVICE_RISK_TABLE = {
    "ftp": "medium",
    "smb": "high",
    "telnet": "high",
    "rdp": "medium",
    "snmp": "medium",
    "mssql": "medium",
    "mysql": "medium",
}

NSE_SCRIPT_MAP = {
    "ftp": ["ftp-anon", "ftp-bounce", "ftp-syst"],
    "http": ["http-title", "http-enum", "http-vuln-cve2017-5638"],
    "https": ["ssl-cert", "ssl-enum-ciphers", "http-title"],
    "ssh": ["ssh2-enum-algos", "ssh-hostkey"],
    "smb": ["smb-os-discovery", "smb-enum-shares", "smb-vuln-ms17-010"],
    "dns": ["dns-recursion", "dns-nsid"],
    "smtp": ["smtp-commands", "smtp-open-relay"],
    "snmp": ["snmp-info", "snmp-processes"],
    "mysql": ["mysql-info", "mysql-empty-password"],
    "mssql": ["ms-sql-info", "ms-sql-empty-password"],
    "rdp": ["rdp-enum-encryption", "rdp-ntlm-info"],
}

OUTDATED_VERSION_THRESHOLDS = {
    "vsftpd": "3.0.5",
    "openssh": "8.9",
    "apache httpd": "2.4.58",
    "nginx": "1.24.0",
    "samba smbd": "4.17.0",
    "samba": "4.17.0",
}

LEGACY_WINDOWS_MARKERS = ("windows xp", "windows 2000", "windows 2003", "windows 7", "windows server 2008")
LEGACY_LINUX_KERNEL_PREFIXES = ("linux 2.", "linux 3.")


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    rationale: str
    port: int | None = None
    service: str | None = None


class RiskEngine:
    def __init__(self, cve_db_path: str | Path | None = None) -> None:
        default_path = Path(__file__).resolve().parent / "data" / "cve_db.json"
        self.cve_db_path = Path(cve_db_path) if cve_db_path else default_path
        self.cve_db = self._load_cve_db()

    def _load_cve_db(self) -> list[dict[str, Any]]:
        with self.cve_db_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def analyze(self, scan: ScanResult | dict[str, Any]) -> dict[str, Any]:
        scan_result = scan if isinstance(scan, ScanResult) else ScanResult.from_dict(scan)
        open_ports = [port for port in scan_result.ports if port.state.lower() == "open"]

        findings: list[Finding] = []
        cve_matches: list[dict[str, Any]] = []

        findings.extend(self._service_findings(open_ports))
        findings.extend(self._port_volume_findings(open_ports))
        findings.extend(self._outdated_version_findings(open_ports))
        findings.extend(self._os_findings(scan_result, open_ports))
        cve_matches.extend(self._match_cves(open_ports))

        for match in cve_matches:
            findings.append(
                Finding(
                    title=f"CVE match: {match['cve_id']}",
                    severity=match["severity"],
                    rationale=match["summary"],
                    port=match.get("port"),
                    service=match.get("service"),
                )
            )

        recommended_nse_scripts = self._select_nse_scripts(open_ports)
        severity_counts = self._severity_counts(findings)
        risk_score = self._calculate_risk_score(findings, len(open_ports))
        overall_severity = self._calculate_overall_severity(findings)

        return {
            "host": scan_result.host,
            "os_name": scan_result.os_name,
            "open_port_count": len(open_ports),
            "risk_score": risk_score,
            "severity_counts": severity_counts,
            "overall_severity": overall_severity,
            "findings": [asdict(finding) for finding in findings],
            "cve_matches": cve_matches,
            "recommended_nse_scripts": recommended_nse_scripts,
        }

    def _service_findings(self, ports: list[PortInfo]) -> list[Finding]:
        findings: list[Finding] = []
        for port in ports:
            service_name = port.service.lower()
            severity = SERVICE_RISK_TABLE.get(service_name)
            if severity:
                findings.append(
                    Finding(
                        title=f"Risky service exposed: {port.service}",
                        severity=severity,
                        rationale=f"{port.service.upper()} is exposed on port {port.port}.",
                        port=port.port,
                        service=port.service,
                    )
                )
        return findings

    def _port_volume_findings(self, ports: list[PortInfo]) -> list[Finding]:
        if len(ports) < 10:
            return []
        return [
            Finding(
                title="Large attack surface",
                severity="critical",
                rationale=f"{len(ports)} open ports were detected, which exceeds the critical threshold of 10.",
            )
        ]

    def _outdated_version_findings(self, ports: list[PortInfo]) -> list[Finding]:
        findings: list[Finding] = []
        for port in ports:
            product_name = self._normalized_product_name(port)
            if not product_name or not port.version:
                continue
            threshold = OUTDATED_VERSION_THRESHOLDS.get(product_name)
            if threshold and self._is_version_less_than(port.version, threshold):
                findings.append(
                    Finding(
                        title=f"Outdated service version: {port.product}",
                        severity="high",
                        rationale=f"Detected version {port.version} is older than recommended baseline {threshold}.",
                        port=port.port,
                        service=port.service,
                    )
                )
        return findings

    def _os_findings(self, scan: ScanResult, ports: list[PortInfo]) -> list[Finding]:
        os_name = scan.os_name.lower()
        findings: list[Finding] = []

        if any(marker in os_name for marker in LEGACY_WINDOWS_MARKERS):
            findings.append(
                Finding(
                    title="Legacy Windows host detected",
                    severity="critical",
                    rationale=f"Operating system '{scan.os_name}' is legacy and likely out of support.",
                )
            )

        if any(os_name.startswith(prefix) for prefix in LEGACY_LINUX_KERNEL_PREFIXES):
            findings.append(
                Finding(
                    title="Legacy Linux kernel detected",
                    severity="high",
                    rationale=f"Operating system '{scan.os_name}' appears to be based on an old Linux kernel line.",
                )
            )

        if "windows" in os_name and any(port.service.lower() == "smb" for port in ports):
            findings.append(
                Finding(
                    title="SMB on Windows host",
                    severity="high",
                    rationale="SMB exposure on a Windows host deserves elevated scrutiny because it is frequently targeted.",
                )
            )

        if not scan.os_name:
            findings.append(
                Finding(
                    title="OS fingerprint unavailable",
                    severity="low",
                    rationale="Operating system data was not provided, reducing confidence in OS-specific risk checks.",
                )
            )

        return findings

    def _match_cves(self, ports: list[PortInfo]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for port in ports:
            product_name = self._normalized_product_name(port)
            for entry in self.cve_db:
                if entry["service"] != port.service.lower():
                    continue
                product_contains = entry.get("product_contains", "").lower()
                if product_contains and product_contains not in product_name:
                    continue
                affected_lt = entry.get("affected_versions_lt")
                if affected_lt and port.version and not self._is_version_less_than(port.version, affected_lt):
                    continue

                matches.append(
                    {
                        "cve_id": entry["cve_id"],
                        "severity": entry["severity"],
                        "summary": entry["summary"],
                        "service": port.service,
                        "port": port.port,
                    }
                )
        return matches

    def _select_nse_scripts(self, ports: list[PortInfo]) -> list[str]:
        selected: set[str] = set()
        for port in ports:
            service_name = port.service.lower()
            for candidate_service, scripts in NSE_SCRIPT_MAP.items():
                if candidate_service == service_name:
                    selected.update(scripts)
        return sorted(selected)

    def _calculate_overall_severity(self, findings: list[Finding]) -> str:
        if not findings:
            return "info"
        highest = max(findings, key=lambda finding: SEVERITY_ORDER[finding.severity])
        return highest.severity

    def _severity_counts(self, findings: list[Finding]) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in findings:
            counts[finding.severity] += 1
        return counts

    def _calculate_risk_score(self, findings: list[Finding], open_port_count: int) -> int:
        weights = {"info": 1, "low": 3, "medium": 8, "high": 15, "critical": 25}
        score = sum(weights[finding.severity] for finding in findings)
        return score + open_port_count

    def _normalized_product_name(self, port: PortInfo) -> str:
        return re.sub(r"\s+", " ", port.product.strip().lower())

    def _is_version_less_than(self, detected: str, baseline: str) -> bool:
        detected_tuple = self._parse_version(detected)
        baseline_tuple = self._parse_version(baseline)
        if not detected_tuple or not baseline_tuple:
            return False
        width = max(len(detected_tuple), len(baseline_tuple))
        detected_tuple += (0,) * (width - len(detected_tuple))
        baseline_tuple += (0,) * (width - len(baseline_tuple))
        return detected_tuple < baseline_tuple

    def _parse_version(self, value: str) -> tuple[int, ...]:
        numbers = re.findall(r"\d+", value)
        return tuple(int(item) for item in numbers)


def analyze_scan(scan: ScanResult | dict[str, Any], cve_db_path: str | Path | None = None) -> dict[str, Any]:
    return RiskEngine(cve_db_path=cve_db_path).analyze(scan)
