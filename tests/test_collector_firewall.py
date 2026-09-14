import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collector", ROOT / "collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class FirewallEventTests(unittest.TestCase):
    def test_provider_drop(self):
        message = (
            "UFWVPS:example IN=eth0 OUT= SRC=203.0.113.10 "
            "DST=198.51.100.20 PROTO=TCP SPT=44000 DPT=23"
        )
        event = collector.firewall_event(100, message, {"example": "Example Hosting"})
        self.assertEqual(event["kind"], "firewall_block")
        self.assertEqual(event["decision"], "Bloqueado")
        self.assertEqual(event["provider"], "Example Hosting")
        self.assertEqual(event["port"], "23")

    def test_general_allow(self):
        message = (
            "[UFW ALLOW] IN=eth0 OUT= SRC=192.0.2.10 DST=198.51.100.20 "
            "PROTO=TCP SPT=54000 DPT=443"
        )
        event = collector.firewall_event(101, message, {})
        self.assertEqual(event["kind"], "firewall_allow")
        self.assertEqual(event["decision"], "Permitido")
        self.assertEqual(event["service"], "HTTPS")

    def test_selective_allow_monitor(self):
        message = (
            "SSALLOW4: IN=eth0 OUT= SRC=192.0.2.11 DST=198.51.100.20 "
            "PROTO=TCP SPT=54001 DPT=80"
        )
        event = collector.firewall_event(101, message, {})
        self.assertEqual(event["kind"], "firewall_allow")
        self.assertEqual(event["decision"], "Permitido")
        self.assertEqual(event["port"], "80")

    def test_general_block(self):
        message = (
            "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.8 DST=198.51.100.20 "
            "PROTO=UDP SPT=53000 DPT=80"
        )
        event = collector.firewall_event(102, message, {})
        self.assertEqual(event["kind"], "firewall_block")
        self.assertEqual(event["protocol"], "UDP")

    def test_reviewed_provider_block(self):
        message = (
            "SSPROVIDER4: IN=eth0 OUT= SRC=203.0.113.9 DST=198.51.100.20 "
            "PROTO=TCP SPT=53000 DPT=3306"
        )
        event = collector.firewall_event(104, message, {})
        self.assertEqual(event["kind"], "firewall_block")
        self.assertEqual(event["decision"], "Bloqueado")
        self.assertEqual(event["provider_slug"], "reviewed_provider")

    def test_audit_is_not_mislabeled_as_allowed(self):
        message = (
            "[UFW AUDIT] IN=eth0 OUT= SRC=203.0.113.8 DST=198.51.100.20 "
            "PROTO=TCP SPT=53000 DPT=22"
        )
        self.assertIsNone(collector.firewall_event(103, message, {}))


if __name__ == "__main__":
    unittest.main()
