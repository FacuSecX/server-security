import importlib.util
import pathlib
import sys
import types
import unittest


try:
    import fcntl  # noqa: F401
except ImportError:
    sys.modules["fcntl"] = types.SimpleNamespace(LOCK_EX=2, flock=lambda *_: None)

MODULE_PATH = pathlib.Path(__file__).parents[1] / "vps" / "server-securityctl.py"
SPEC = importlib.util.spec_from_file_location("server_securityctl", MODULE_PATH)
securityctl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(securityctl)


class SecurityControllerTests(unittest.TestCase):
    def test_public_ip_is_canonicalized(self):
        self.assertEqual(str(securityctl.parse_public_ip("8.8.8.8")), "8.8.8.8")

    def test_management_and_proxy_networks_are_protected(self):
        for address in ("100.64.0.1", "fd7a:115c:a1e0::1"):
            with self.subTest(address=address), self.assertRaises(securityctl.ControlError):
                securityctl.parse_public_ip(address)

    def test_private_and_loopback_addresses_are_rejected(self):
        for address in ("127.0.0.1", "10.0.0.1", "192.168.1.20", "::1"):
            with self.subTest(address=address), self.assertRaises(securityctl.ControlError):
                securityctl.parse_public_ip(address)

    def test_rules_apply_to_every_port(self):
        for version in (4, 6):
            log_rule, drop_rule = securityctl.rule_specs(version)
            self.assertNotIn("--dport", log_rule)
            self.assertNotIn("--dport", drop_rule)
            self.assertEqual(drop_rule[-1], "DROP")

    def test_provider_prefixes_are_canonical_and_protected(self):
        self.assertEqual(str(securityctl.parse_public_network("8.8.8.0/24")), "8.8.8.0/24")
        for prefix in ("10.0.0.0/8", "100.64.0.0/10", "fd7a:115c:a1e0::/48"):
            with self.subTest(prefix=prefix), self.assertRaises(securityctl.ControlError):
                securityctl.parse_public_network(prefix)

    def test_provider_digest_is_order_independent(self):
        first = securityctl.prefix_digest("AS15169", ["8.8.8.0/24", "8.8.4.0/24"])
        second = securityctl.prefix_digest("15169", ["8.8.4.0/24", "8.8.8.0/24"])
        self.assertEqual(first, second)

    def test_provider_rules_apply_to_every_port(self):
        for version in (4, 6):
            log_rule, drop_rule = securityctl.provider_rule_specs(version)
            self.assertNotIn("--dport", log_rule)
            self.assertNotIn("--dport", drop_rule)
            self.assertEqual(drop_rule[-1], "DROP")

    def test_provider_payload_requires_exact_review_digest(self):
        prefixes = ["8.8.4.0/24", "8.8.8.0/24"]
        digest = securityctl.prefix_digest("AS15169", prefixes)
        item = securityctl.provider_payload({
            "asn": "AS15169", "name": "Example Hosting",
            "prefixes": prefixes, "approval_digest": digest,
            "reason": "Revisión confirmada",
        })
        self.assertEqual(item["asn"], "AS15169")
        self.assertEqual(item["prefix_digest"], digest)
        self.assertEqual(item["ipv4"], 2)
        with self.assertRaises(securityctl.ControlError):
            securityctl.provider_payload({
                "asn": "AS15169", "name": "Example Hosting",
                "prefixes": prefixes, "approval_digest": "0" * 64,
            })

    def test_accept_monitor_removes_original_comment_only(self):
        original = [
            "-p", "tcp", "-s", "173.245.48.0/20", "--dport", "443",
            "-m", "comment", "--comment", "Cloudflare HTTPS",
        ]
        cleaned = securityctl.strip_comment_matches(original)
        self.assertEqual(cleaned, [
            "-p", "tcp", "-s", "173.245.48.0/20", "--dport", "443",
        ])

    def test_report_period_is_strictly_bounded(self):
        self.assertEqual(securityctl.report_minutes({"minutes": 1440}), 1440)
        for value in (0, 10081, "1440", True, None):
            with self.subTest(value=value), self.assertRaises(securityctl.ControlError):
                securityctl.report_minutes({"minutes": value})

    def test_report_command_uses_only_the_fixed_generator(self):
        self.assertEqual(securityctl.report_command(2880), [
            "/usr/bin/bash",
            "/opt/server-security/ssh-report.sh",
            "--since",
            "2880 minutes ago",
            "--all",
            "--output-dir",
            "/var/lib/server-security/reports",
        ])


if __name__ == "__main__":
    unittest.main()
