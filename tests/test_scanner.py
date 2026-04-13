import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from scanner import AGGRESSIVE_PROFILE, BASIC_PROFILE, DEEP_PROFILE, SCRIPT_PROFILE, Scanner
from scan_engine.models import ReconSnapshot


TEST_ROOT = Path(__file__).resolve().parent
TMP_ROOT = TEST_ROOT / "_tmp"
TMP_ROOT.mkdir(exist_ok=True)


SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" reason="user-set" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="demo.local" type="user" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" />
        <service name="ssh" product="OpenSSH" version="8.4" />
        <script id="banner" output="SSH-2.0-OpenSSH_8.4" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="98" />
    </os>
  </host>
</nmaprun>
"""


class ScannerTests(unittest.TestCase):
    def test_parse_xml_returns_scan_result_and_banner_data(self) -> None:
        xml_path = self._workspace_file("sample-scan.xml")
        xml_path.write_text(SAMPLE_XML, encoding="utf-8")

        scanner = Scanner(nmap_path="nmap", output_dir=TMP_ROOT)
        result = scanner.parse_xml(xml_path)

        self.assertEqual(result.host, "192.168.1.10")
        self.assertEqual(result.os_name, "Linux 5.15")
        self.assertEqual(result.os_accuracy, 98)
        self.assertEqual(len(result.ports), 2)
        self.assertEqual(result.ports[0].service, "ssh")
        self.assertEqual(result.ports[0].extra["banner"], "SSH-2.0-OpenSSH_8.4")
        self.assertEqual(result.ports[0].extra["scripts"]["banner"], "SSH-2.0-OpenSSH_8.4")
        self.assertEqual(result.raw["xml_path"], str(xml_path))

    def test_choose_follow_up_profile_uses_open_port_count(self) -> None:
        scanner = Scanner(nmap_path="nmap", output_dir=".", deep_threshold=2, aggressive_threshold=4)

        basic_only = scanner._choose_follow_up_profiles(
            scanner.parse_xml(self._write_xml_with_open_ports(1))
        )
        deep = scanner._choose_follow_up_profiles(scanner.parse_xml(self._write_xml_with_open_ports(2)))
        aggressive = scanner._choose_follow_up_profiles(
            scanner.parse_xml(self._write_xml_with_open_ports(4))
        )

        self.assertEqual(basic_only, [])
        self.assertEqual(deep, [DEEP_PROFILE])
        self.assertEqual(aggressive, [DEEP_PROFILE, AGGRESSIVE_PROFILE])

    def test_scan_runs_basic_deep_and_script_followup(self) -> None:
        scanner = Scanner(nmap_path="nmap", output_dir=TMP_ROOT, deep_threshold=1, aggressive_threshold=3, recon_providers=[])
        observed: list[tuple[str, tuple[str, ...], str, list[str] | None]] = []

        def fake_run_and_parse(profile, target, xml_path, plan, extra_args=(), notes=None):
            observed.append((profile.name, extra_args, str(xml_path), notes))
            if profile == BASIC_PROFILE:
                return scanner.parse_xml(self._write_xml_with_open_ports(1))
            if profile == DEEP_PROFILE:
                return scanner.parse_xml(self._write_xml_with_services([(22, "ssh"), (445, "smb")]))
            if profile == SCRIPT_PROFILE:
                result = scanner.parse_xml(self._write_xml_with_services([(22, "ssh"), (445, "smb")], with_banner=True))
                plan.recommended_nse_scripts = ["smb-vuln-ms17-010", "ssh-hostkey"]
                return result
            self.fail(f"Unexpected profile: {profile.name}")

        with patch.object(scanner, "_run_and_parse", side_effect=fake_run_and_parse):
            result = scanner.scan("scanme.local", xml_path=self._workspace_file("scanme.xml"), run_recon=False)

        self.assertEqual([item[0] for item in observed], ["basic", "deep", "scripts"])
        self.assertEqual(result.host, "192.168.1.10")
        self.assertEqual(sum(port.state == "open" for port in result.ports), 2)
        self.assertIn("scan_engine", result.raw)
        self.assertIn("smb-vuln-ms17-010", result.raw["scan_engine"]["recommended_nse_scripts"])
        self.assertIn("ssh-hostkey", result.raw["scan_engine"]["recommended_nse_scripts"])

    def test_grab_banners_invokes_banner_script_for_selected_ports(self) -> None:
        scanner = Scanner(nmap_path="nmap", output_dir=TMP_ROOT)
        calls: list[tuple[str, Path, tuple[str, ...]]] = []

        def fake_run_nmap(*, target, xml_path, extra_args):
            calls.append((target, xml_path, extra_args))
            xml_path.write_text(self._build_xml(open_ports=1, with_banner=True), encoding="utf-8")

        xml_path = self._workspace_file("banner.xml")
        with patch.object(scanner, "_run_nmap", side_effect=fake_run_nmap):
            result = scanner.grab_banners("192.168.1.10", [80, 22, 80], xml_path=xml_path)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "192.168.1.10")
        self.assertIn("--script", calls[0][2])
        self.assertIn("banner", calls[0][2])
        self.assertIn("22,80", calls[0][2])
        self.assertIn("banner", result.ports[0].extra["scripts"])

    def test_scan_attaches_recon_snapshots(self) -> None:
        class FakeProvider:
            name = "fake"

            def collect(self, result):
                return ReconSnapshot(provider="fake", summary=f"Intel for {result.host}", data={"ok": True})

        scanner = Scanner(nmap_path="nmap", output_dir=TMP_ROOT, recon_providers=[FakeProvider()])

        def fake_run_and_parse(profile, target, xml_path, plan, extra_args=(), notes=None):
            return scanner.parse_xml(self._write_xml_with_services([(443, "https")]))

        with patch.object(scanner, "_run_and_parse", side_effect=fake_run_and_parse):
            result = scanner.scan("scanme.local", run_recommended_scripts=False)

        self.assertEqual(result.raw["scan_engine"]["recon"][0]["provider"], "fake")

    def _write_xml_with_open_ports(self, count: int) -> Path:
        xml_path = self._workspace_file("open-ports.xml")
        xml_path.write_text(self._build_xml(open_ports=count), encoding="utf-8")
        return xml_path

    def _write_xml_with_services(self, services: list[tuple[int, str]], with_banner: bool = False) -> Path:
        xml_path = self._workspace_file("services.xml")
        xml_path.write_text(self._build_xml_for_services(services, with_banner=with_banner), encoding="utf-8")
        return xml_path

    def _workspace_file(self, suffix: str) -> Path:
        path = TMP_ROOT / f"{uuid.uuid4().hex}-{suffix}"
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return path

    def _build_xml(self, open_ports: int, with_banner: bool = False) -> str:
        ports = []
        for index in range(open_ports):
            port_id = 20 + index
            script = '<script id="banner" output="example banner" />' if with_banner else ""
            ports.append(
                f"""
      <port protocol="tcp" portid="{port_id}">
        <state state="open" reason="syn-ack" />
        <service name="http" product="nginx" version="1.24.0" />
        {script}
      </port>"""
            )

        ports_block = "".join(ports)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <ports>{ports_block}
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="98" />
    </os>
  </host>
</nmaprun>
"""

    def _build_xml_for_services(self, services: list[tuple[int, str]], with_banner: bool = False) -> str:
        ports = []
        for port_id, service_name in services:
            script = '<script id="banner" output="example banner" />' if with_banner else ""
            product = "OpenSSH" if service_name == "ssh" else "Samba smbd" if service_name == "smb" else "Apache httpd"
            version = "8.4" if service_name == "ssh" else "4.6.2" if service_name == "smb" else "2.4.58"
            ports.append(
                f"""
      <port protocol="tcp" portid="{port_id}">
        <state state="open" reason="syn-ack" />
        <service name="{service_name}" product="{product}" version="{version}" />
        {script}
      </port>"""
            )

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <ports>{''.join(ports)}
    </ports>
    <os>
      <osmatch name="Windows 7 Professional" accuracy="98" />
    </os>
  </host>
</nmaprun>
"""


if __name__ == "__main__":
    unittest.main()
