import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import netdesk

ROOT = Path(__file__).resolve().parents[1]


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((ROOT / "examples/healthy.json").read_text(encoding="utf-8"))

    def codes(self):
        return [f["code"] for f in netdesk.audit(netdesk.parse_plan(self.plan))["findings"]]

    def test_clean_plan(self):
        self.assertEqual(self.codes(), [])

    def test_fault_injection_expected_counts(self):
        broken = json.loads((ROOT / "examples/broken.json").read_text(encoding="utf-8"))
        report = netdesk.audit(netdesk.parse_plan(broken))
        self.assertEqual(report["summary"]["findings"], 11)
        self.assertEqual({f["code"] for f in report["findings"]}, {
            "GATEWAY_INVALID", "DHCP_RANGE_INVALID", "GATEWAY_IN_DHCP", "SUBNET_OVERLAP",
            "DEVICE_IP_INVALID", "DEVICE_USES_GATEWAY", "DUPLICATE_IP", "STATIC_IN_DHCP", "UNKNOWN_VLAN"})

    def test_duplicate_ip_in_same_vlan(self):
        self.plan["devices"][1]["ip"] = self.plan["devices"][0]["ip"]
        self.assertEqual(self.codes(), ["DUPLICATE_IP"])

    def test_gateway_not_in_subnet(self):
        self.plan["vlans"][0]["gateway"] = "10.1.1.1"
        self.assertIn("GATEWAY_INVALID", self.codes())

    def test_network_and_broadcast_not_endpoints(self):
        for ip in ("192.168.10.0", "192.168.10.255"):
            with self.subTest(ip=ip):
                self.plan["devices"][0]["ip"] = ip
                self.assertIn("DEVICE_IP_INVALID", self.codes())

    def test_dhcp_inclusive_boundaries(self):
        for ip in ("192.168.10.100", "192.168.10.199"):
            with self.subTest(ip=ip):
                self.plan["devices"][0]["ip"] = ip
                self.assertIn("STATIC_IN_DHCP", self.codes())

    def test_dhcp_invalid_ranges(self):
        for start, end in [("192.168.10.200", "192.168.10.100"),
                           ("192.168.10.0", "192.168.10.199"),
                           ("192.168.10.100", "192.168.10.255"),
                           ("192.168.11.10", "192.168.11.20")]:
            with self.subTest(start=start, end=end):
                self.plan["vlans"][0]["dhcp"] = {"start": start, "end": end}
                self.assertIn("DHCP_RANGE_INVALID", self.codes())

    def test_adjacent_subnets_are_not_overlapping(self):
        self.plan["vlans"][0].update(subnet="192.168.10.0/25", dhcp=None)
        self.plan["vlans"][1].update(subnet="192.168.10.128/25", gateway="192.168.10.129")
        self.assertNotIn("SUBNET_OVERLAP", self.codes())

    def test_contained_subnet_overlap(self):
        self.plan["vlans"][1].update(subnet="192.168.10.128/25", gateway="192.168.10.129")
        self.assertIn("SUBNET_OVERLAP", self.codes())

    def test_unknown_vlan_is_reported(self):
        self.plan["devices"][0]["vlan_id"] = 77
        self.assertIn("UNKNOWN_VLAN", self.codes())

    def test_gateway_collision(self):
        self.plan["devices"][0]["ip"] = "192.168.10.1"
        self.assertIn("DEVICE_USES_GATEWAY", self.codes())

    def test_html_escapes_untrusted_text(self):
        payload = '<script>alert("x")</script>'
        self.plan["site"] = payload
        self.plan["devices"][0].update(name=payload, ip="10.0.0.1")
        html = netdesk.html_report(netdesk.audit(netdesk.parse_plan(self.plan)))
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("default-src 'none'", html)

    def test_schema_rejects_bad_inputs(self):
        cases = [None, [], {}, {**self.plan, "extra": True}]
        for key, value in [("id", True), ("id", 4095), ("gateway", "::1"),
                           ("gateway", 42), ("subnet", "192.168.10.1/24"),
                           ("subnet", "192.168.10.0/31"), ("subnet", "192.168.10.0"),
                           ("dhcp", []), ("name", "")]:
            candidate = copy.deepcopy(self.plan)
            candidate["vlans"][0][key] = value
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(netdesk.PlanError):
                    netdesk.parse_plan(candidate)

    def test_duplicate_identifiers(self):
        for target, key in [("vlans", "id"), ("devices", "name")]:
            candidate = copy.deepcopy(self.plan)
            candidate[target][1][key] = candidate[target][0][key]
            with self.subTest(target=target), self.assertRaises(netdesk.PlanError):
                netdesk.parse_plan(candidate)


class CLITests(unittest.TestCase):
    def run_cli(self, plan, out):
        return subprocess.run([sys.executable, str(ROOT / "netdesk.py"), str(plan), "--out", str(out)],
                              capture_output=True, text=True, timeout=10)

    def test_exit_codes_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            for filename, code in [("healthy.json", 0), ("broken.json", 1)]:
                out = Path(tmp) / filename
                result = self.run_cli(ROOT / "examples" / filename, out)
                self.assertEqual(result.returncode, code, result.stderr)
                report = json.loads((out / "audit.json").read_text(encoding="utf-8"))
                self.assertEqual(report["summary"]["status"], "pass" if code == 0 else "review")
                self.assertIn("<table>", (out / "audit.html").read_text(encoding="utf-8"))

    def test_malformed_duplicate_and_missing_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp) / "input.json", Path(tmp) / "reports"
            for content in ('{', '{"site":"a","site":"b"}', 'null', '{"vlans":null}'):
                src.write_text(content, encoding="utf-8")
                result = self.run_cli(src, out)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(out.exists())
            self.assertEqual(self.run_cli(Path(tmp) / "missing.json", out).returncode, 2)

    def test_oversized_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "large.json"
            src.write_bytes(b" " * (netdesk.MAX_BYTES + 1))
            self.assertEqual(self.run_cli(src, Path(tmp) / "reports").returncode, 2)


if __name__ == "__main__":
    unittest.main()
