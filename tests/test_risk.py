import unittest

from risk_engine.risk import analyze_scan


class RiskEngineTests(unittest.TestCase):
    def test_service_risk_and_outdated_logic(self) -> None:
        report = analyze_scan(
            {
                "host": "192.168.1.10",
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
            }
        )

        severities = {item["severity"] for item in report["findings"]}
        titles = {item["title"] for item in report["findings"]}

        self.assertIn("medium", severities)
        self.assertIn("high", severities)
        self.assertIn("Risky service exposed: ftp", titles)
        self.assertIn("Outdated service version: vsftpd", titles)
        self.assertEqual(report["overall_severity"], "high")
        self.assertGreater(report["risk_score"], 0)
        self.assertEqual(report["severity_counts"]["high"], 2)

    def test_critical_when_ten_or_more_ports_are_open(self) -> None:
        report = analyze_scan(
            {
                "host": "10.0.0.5",
                "os_name": "Linux 5.15",
                "ports": [
                    {"port": port, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.58", "state": "open"}
                    for port in range(20, 30)
                ],
            }
        )

        self.assertEqual(report["open_port_count"], 10)
        self.assertEqual(report["overall_severity"], "critical")
        self.assertGreaterEqual(report["risk_score"], 35)

    def test_os_flags_cve_mapping_and_nse_selection(self) -> None:
        report = analyze_scan(
            {
                "host": "10.10.10.10",
                "os_name": "Windows 7 Professional",
                "ports": [
                    {
                        "port": 445,
                        "protocol": "tcp",
                        "service": "smb",
                        "product": "Samba smbd",
                        "version": "4.6.2",
                        "state": "open",
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "8.4",
                        "state": "open",
                    },
                ],
            }
        )

        finding_titles = {item["title"] for item in report["findings"]}

        self.assertIn("Legacy Windows host detected", finding_titles)
        self.assertIn("SMB on Windows host", finding_titles)
        self.assertTrue(any(match["cve_id"] == "CVE-2017-7494" for match in report["cve_matches"]))
        self.assertIn("smb-vuln-ms17-010", report["recommended_nse_scripts"])
        self.assertIn("ssh-hostkey", report["recommended_nse_scripts"])
        self.assertEqual(report["overall_severity"], "critical")
        self.assertEqual(report["severity_counts"]["critical"], 2)


if __name__ == "__main__":
    unittest.main()
