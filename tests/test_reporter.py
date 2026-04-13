import unittest
import uuid
from pathlib import Path

from risk_engine.reporter import export_report, rank_targets_from_scans, report_to_html, report_to_text


TEST_ROOT = Path(__file__).resolve().parent
TMP_ROOT = TEST_ROOT / "_tmp"
TMP_ROOT.mkdir(exist_ok=True)


class ReporterTests(unittest.TestCase):
    def test_text_and_html_rendering_include_key_fields(self) -> None:
        report = {
            "host": "192.168.1.10",
            "os_name": "Windows 7 Professional",
            "open_port_count": 2,
            "risk_score": 51,
            "overall_severity": "critical",
            "findings": [
                {
                    "title": "Legacy Windows host detected",
                    "severity": "critical",
                    "rationale": "Operating system is legacy.",
                    "port": None,
                    "service": None,
                }
            ],
            "recommended_nse_scripts": ["smb-vuln-ms17-010"],
            "raw": {
                "scan_engine": {
                    "profiles": ["basic", "deep", "scripts"],
                    "run_history": [{"profile": "basic", "open_port_count": 2}],
                    "recon": [{"provider": "reverse_dns", "summary": "Resolved reverse DNS hostname demo.local"}],
                }
            },
        }

        text_output = report_to_text(report)
        html_output = report_to_html(report)

        self.assertIn("Risk score: 51", text_output)
        self.assertIn("Legacy Windows host detected", text_output)
        self.assertIn("Profiles run: basic, deep, scripts", text_output)
        self.assertIn("smb-vuln-ms17-010", html_output)
        self.assertIn("CRITICAL", html_output)
        self.assertIn("Recon Sources", html_output)

    def test_export_report_writes_files(self) -> None:
        report = {
            "host": "192.168.1.10",
            "os_name": "Linux",
            "open_port_count": 1,
            "risk_score": 9,
            "overall_severity": "medium",
            "findings": [],
            "recommended_nse_scripts": [],
        }

        txt_path = TMP_ROOT / f"{uuid.uuid4().hex}-report.txt"
        html_path = TMP_ROOT / f"{uuid.uuid4().hex}-report.html"
        self.addCleanup(lambda: txt_path.unlink(missing_ok=True))
        self.addCleanup(lambda: html_path.unlink(missing_ok=True))

        export_report(report, txt_path)
        export_report(report, html_path)

        self.assertTrue(txt_path.exists())
        self.assertTrue(html_path.exists())
        self.assertIn("Overall severity: medium", txt_path.read_text(encoding="utf-8"))
        self.assertIn("<html", html_path.read_text(encoding="utf-8").lower())

    def test_rank_targets_orders_highest_risk_first(self) -> None:
        ranked = rank_targets_from_scans(
            [
                {
                    "host": "192.168.1.20",
                    "os_name": "Ubuntu Linux 22.04",
                    "ports": [
                        {
                            "port": 21,
                            "protocol": "tcp",
                            "service": "ftp",
                            "product": "vsftpd",
                            "version": "3.0.3",
                            "state": "open",
                        }
                    ],
                },
                {
                    "host": "192.168.1.10",
                    "os_name": "Windows 7 Professional",
                    "ports": [
                        {
                            "port": 445,
                            "protocol": "tcp",
                            "service": "smb",
                            "product": "Samba smbd",
                            "version": "4.6.2",
                            "state": "open",
                        }
                    ],
                },
            ]
        )

        self.assertEqual(ranked[0]["host"], "192.168.1.10")
        self.assertGreater(ranked[0]["risk_score"], ranked[1]["risk_score"])


if __name__ == "__main__":
    unittest.main()
