from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from risk_engine.models import PortInfo, ScanResult
from risk_engine.risk import RiskEngine

from .models import NmapRunRecord, ReconSnapshot, ScanExecutionPlan, ScanProfile, ScanSummary
from .profiles import AGGRESSIVE_PROFILE, BASIC_PROFILE, BANNER_PROFILE, DEEP_PROFILE, DEFAULT_THRESHOLDS, SCRIPT_PROFILE
from .recon import ReconProvider, default_recon_providers


DEFAULT_NMAP_CANDIDATES = (
    "nmap",
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)


class ScannerError(RuntimeError):
    """Raised when the Nmap scanner cannot complete a scan."""


class Scanner:
    def __init__(
        self,
        nmap_path: str | Path | None = None,
        output_dir: str | Path | None = None,
        deep_threshold: int = DEFAULT_THRESHOLDS["deep"],
        aggressive_threshold: int = DEFAULT_THRESHOLDS["aggressive"],
        recon_providers: list[ReconProvider] | None = None,
    ) -> None:
        self.nmap_path = str(nmap_path or self._resolve_nmap_path())
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "scan_outputs"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.deep_threshold = deep_threshold
        self.aggressive_threshold = aggressive_threshold
        self.risk_engine = RiskEngine()
        self.recon_providers = recon_providers if recon_providers is not None else default_recon_providers()

    def scan(
        self,
        target: str,
        xml_path: str | Path | None = None,
        *,
        run_recon: bool = True,
        run_recommended_scripts: bool = True,
    ) -> ScanResult:
        target = target.strip()
        if not target:
            raise ValueError("target must not be empty")

        destination = Path(xml_path) if xml_path else self.output_dir / self._xml_name_for_target(target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        plan = ScanExecutionPlan(target=target)

        initial_result = self._run_and_parse(BASIC_PROFILE, target, destination, plan)
        follow_up_profiles = self._choose_follow_up_profiles(initial_result)

        result = initial_result
        for profile in follow_up_profiles:
            result = self._run_and_parse(profile, target, destination, plan)

        report = self.risk_engine.analyze(result)
        recommended_scripts = report.get("recommended_nse_scripts", [])
        if run_recommended_scripts and recommended_scripts:
            result = self._run_recommended_scripts(result, target, destination, recommended_scripts, plan)
            report = self.risk_engine.analyze(result)
            recommended_scripts = report.get("recommended_nse_scripts", [])

        plan.recommended_nse_scripts = recommended_scripts
        if run_recon:
            plan.recon_snapshots = self._collect_recon(result)

        result.raw.update(self._build_plan_metadata(plan))
        return result

    def grab_banners(self, target: str, ports: list[int], xml_path: str | Path | None = None) -> ScanResult:
        target = target.strip()
        if not target:
            raise ValueError("target must not be empty")
        if not ports:
            raise ValueError("ports must not be empty")

        destination = Path(xml_path) if xml_path else self.output_dir / self._xml_name_for_target(f"{target}-banner")
        destination.parent.mkdir(parents=True, exist_ok=True)
        port_spec = ",".join(str(int(port)) for port in sorted(set(ports)))

        self._run_nmap(
            target=target,
            xml_path=destination,
            extra_args=(*BANNER_PROFILE.args, "-p", port_spec),
        )
        return self.parse_xml(destination)

    def summarize(self, result: ScanResult) -> ScanSummary:
        open_ports = [port for port in result.ports if port.state.lower() == "open"]
        metadata = result.raw.get("scan_engine", {})
        services = sorted({port.service for port in open_ports if port.service})
        return ScanSummary(
            target=result.host or metadata.get("target", ""),
            open_ports=len(open_ports),
            services=services,
            profiles_run=[entry["profile"] for entry in metadata.get("run_history", [])],
            recommended_nse_scripts=metadata.get("recommended_nse_scripts", []),
            recon_sources=[entry["provider"] for entry in metadata.get("recon", [])],
        )

    def parse_xml(self, xml_path: str | Path) -> ScanResult:
        xml_file = Path(xml_path)
        root = ET.parse(xml_file).getroot()

        host_node = root.find("host")
        if host_node is None:
            raise ScannerError(f"No host data found in XML output: {xml_file}")

        address_node = host_node.find("address")
        host = address_node.get("addr", "") if address_node is not None else ""

        os_name = ""
        os_accuracy: int | None = None
        best_osmatch = host_node.find("./os/osmatch")
        if best_osmatch is not None:
            os_name = best_osmatch.get("name", "") or ""
            accuracy = best_osmatch.get("accuracy")
            os_accuracy = int(accuracy) if accuracy and accuracy.isdigit() else None

        ports: list[PortInfo] = []
        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            service = port_node.find("service")
            state_name = state.get("state", "unknown") if state is not None else "unknown"
            script_output = self._extract_script_output(port_node)
            extra: dict[str, Any] = {}
            if script_output:
                extra["scripts"] = script_output
                if "banner" in script_output:
                    extra["banner"] = script_output["banner"]

            ports.append(
                PortInfo(
                    port=int(port_node.get("portid", "0")),
                    protocol=port_node.get("protocol", "tcp"),
                    service=(service.get("name", "unknown") if service is not None else "unknown") or "unknown",
                    product=service.get("product", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                    state=state_name,
                    extra=extra,
                )
            )

        raw = self._host_to_dict(host_node)
        raw["xml_path"] = str(xml_file)
        return ScanResult(host=host, os_name=os_name, os_accuracy=os_accuracy, ports=ports, raw=raw)

    def _run_and_parse(
        self,
        profile: ScanProfile,
        target: str,
        xml_path: Path,
        plan: ScanExecutionPlan,
        extra_args: tuple[str, ...] = (),
        notes: list[str] | None = None,
    ) -> ScanResult:
        command = self._run_nmap(target=target, xml_path=xml_path, extra_args=(*profile.args, *extra_args))
        result = self.parse_xml(xml_path)
        open_port_count = sum(1 for port in result.ports if port.state.lower() == "open")
        plan.selected_profiles.append(profile)
        plan.run_history.append(
            NmapRunRecord(
                profile_name=profile.name,
                xml_path=xml_path,
                command=tuple(command),
                open_port_count=open_port_count,
                notes=notes or [],
            )
        )
        return result

    def _run_recommended_scripts(
        self,
        result: ScanResult,
        target: str,
        xml_path: Path,
        scripts: list[str],
        plan: ScanExecutionPlan,
    ) -> ScanResult:
        open_ports = sorted({port.port for port in result.ports if port.state.lower() == "open"})
        if not open_ports:
            return result

        unique_scripts = sorted(set(scripts))
        return self._run_and_parse(
            SCRIPT_PROFILE,
            target,
            xml_path,
            plan,
            extra_args=("--script", ",".join(unique_scripts), "-p", ",".join(str(port) for port in open_ports)),
            notes=[f"Ran recommended NSE scripts: {', '.join(unique_scripts)}"],
        )

    def _collect_recon(self, result: ScanResult) -> list[ReconSnapshot]:
        snapshots: list[ReconSnapshot] = []
        for provider in self.recon_providers:
            snapshot = provider.collect(result)
            if snapshot is not None:
                snapshots.append(snapshot)
        return snapshots

    def _build_plan_metadata(self, plan: ScanExecutionPlan) -> dict[str, Any]:
        return {
            "scan_engine": {
                "target": plan.target,
                "profiles": [profile.name for profile in plan.selected_profiles],
                "recommended_nse_scripts": plan.recommended_nse_scripts,
                "run_history": [
                    {
                        "profile": run.profile_name,
                        "xml_path": str(run.xml_path),
                        "command": list(run.command),
                        "open_port_count": run.open_port_count,
                        "notes": run.notes,
                    }
                    for run in plan.run_history
                ],
                "recon": [
                    {
                        "provider": snapshot.provider,
                        "summary": snapshot.summary,
                        "data": snapshot.data,
                    }
                    for snapshot in plan.recon_snapshots
                ],
            }
        }

    def _choose_follow_up_profiles(self, result: ScanResult) -> list[ScanProfile]:
        open_port_count = sum(1 for port in result.ports if port.state.lower() == "open")
        profiles: list[ScanProfile] = []
        if open_port_count >= self.deep_threshold:
            profiles.append(DEEP_PROFILE)
        if open_port_count >= self.aggressive_threshold:
            profiles.append(AGGRESSIVE_PROFILE)
        return profiles

    def _run_nmap(self, target: str, xml_path: Path, extra_args: tuple[str, ...]) -> list[str]:
        with TemporaryDirectory(prefix="nmap-xml-") as temp_dir:
            generated_xml = Path(temp_dir) / "scan.xml"
            command = [self.nmap_path, *extra_args, "-oX", str(generated_xml), target]
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )

            if completed.returncode != 0:
                stderr = completed.stderr.strip()
                stdout = completed.stdout.strip()
                details = stderr or stdout or "unknown error"
                raise ScannerError(f"Nmap scan failed for {target}: {details}")

            if not generated_xml.exists():
                raise ScannerError(f"Nmap did not produce XML output for {target}")

            xml_path.write_text(generated_xml.read_text(encoding="utf-8"), encoding="utf-8")
            return command

    def _resolve_nmap_path(self) -> str:
        for candidate in DEFAULT_NMAP_CANDIDATES:
            resolved = shutil.which(candidate) if "\\" not in candidate else candidate
            if resolved and Path(resolved).exists():
                return resolved
        raise ScannerError("Unable to locate nmap executable")

    def _xml_name_for_target(self, target: str) -> str:
        sanitized = "".join(char if char.isalnum() else "_" for char in target).strip("_")
        return f"{sanitized or 'scan'}.xml"

    def _extract_script_output(self, port_node: ET.Element) -> dict[str, str]:
        outputs: dict[str, str] = {}
        for script in port_node.findall("script"):
            script_id = script.get("id", "").strip()
            script_output = script.get("output", "").strip()
            if script_id and script_output:
                outputs[script_id] = script_output
        return outputs

    def _host_to_dict(self, host_node: ET.Element) -> dict[str, Any]:
        return {
            "status": host_node.find("status").attrib if host_node.find("status") is not None else {},
            "addresses": [address.attrib for address in host_node.findall("address")],
            "hostnames": [hostname.attrib for hostname in host_node.findall("./hostnames/hostname")],
            "ports": [
                {
                    "protocol": port.get("protocol", ""),
                    "portid": port.get("portid", ""),
                    "state": port.find("state").attrib if port.find("state") is not None else {},
                    "service": port.find("service").attrib if port.find("service") is not None else {},
                    "scripts": [script.attrib for script in port.findall("script")],
                }
                for port in host_node.findall("./ports/port")
            ],
            "os": [match.attrib for match in host_node.findall("./os/osmatch")],
        }


def scan_target(
    target: str,
    *,
    nmap_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    xml_path: str | Path | None = None,
    run_recon: bool = True,
    run_recommended_scripts: bool = True,
) -> ScanResult:
    scanner = Scanner(nmap_path=nmap_path, output_dir=output_dir)
    return scanner.scan(
        target=target,
        xml_path=xml_path,
        run_recon=run_recon,
        run_recommended_scripts=run_recommended_scripts,
    )
