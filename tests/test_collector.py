import json
import unittest
from unittest.mock import patch

import collector


class CollectorTests(unittest.TestCase):
    def test_provider_counters_are_combined(self):
        ipv4 = '[44:1921] -A ufw-before-input -m set --match-set uvp_example4 src -m comment --comment "UFW-VPS: Example Hosting" -j DROP\n'
        ipv6 = '[3:180] -A ufw6-before-input -m set --match-set uvp_example6 src -m comment --comment "UFW-VPS: Example Hosting" -j DROP\n'

        def fake_run(command, timeout=35):
            if command[0] == "ipset":
                return (
                    "add uvp_example4 192.0.2.0/24\n"
                    "add uvp_example4 198.51.100.0/24\n"
                    "add uvp_example6 2001:db8::/32\n"
                )
            return ipv6 if command[0] == "ip6tables-save" else ipv4

        with patch.object(collector, "run", fake_run), patch.object(collector.shutil, "which", lambda _: True):
            rows = collector.provider_snapshots()

        self.assertEqual(rows[0]["name"], "Example Hosting")
        self.assertEqual(rows[0]["packets"], 47)
        self.assertEqual(rows[0]["ipv4_packets"], 44)
        self.assertEqual(rows[0]["ipv6_packets"], 3)
        self.assertEqual(rows[0]["ipv4_entries"], 2)
        self.assertEqual(rows[0]["ipv6_entries"], 1)
        self.assertEqual(rows[0]["entries"], 3)

    def test_firewall_and_ssh_events_are_parsed(self):
        kernel_row = json.dumps({
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "MESSAGE": "UFWVPS:example IN=eth0 SRC=203.0.113.10 DST=198.51.100.20 PROTO=TCP SPT=45670 DPT=23",
        })
        ssh_row = json.dumps({
            "__REALTIME_TIMESTAMP": "1700000001000000",
            "MESSAGE": "Failed publickey for invalid user admin from 203.0.113.7 port 41122 ssh2",
        })

        def fake_run(command, timeout=35):
            return kernel_row if "-k" in command else ssh_row

        with patch.object(collector, "run", fake_run):
            rows = collector.journal_events(0, {"example": "Example Hosting"})

        self.assertEqual(rows[0]["provider"], "Example Hosting")
        self.assertEqual(rows[0]["service"], "Telnet")
        self.assertEqual(rows[1]["kind"], "ssh_failure")
        self.assertEqual(rows[1]["ssh_user"], "admin")

    def test_ufw_and_oneshot_services_are_reported_correctly(self):
        def fake_run(command, timeout=35):
            if command[:2] == ["ufw", "status"]:
                return "Status: active\n"
            unit = command[2]
            if unit == "ufw-vps-providers.service":
                return "LoadState=loaded\nActiveState=inactive\nSubState=dead\nType=oneshot\nResult=success\n"
            if unit == "ufw.service":
                return "LoadState=loaded\nActiveState=inactive\nSubState=dead\nType=oneshot\nResult=success\n"
            return "LoadState=loaded\nActiveState=active\nSubState=running\nType=simple\nResult=success\n"

        with patch.object(collector, "run", fake_run):
            states = {row["unit"]: row["state"] for row in collector.service_states()}

        self.assertEqual(states["ufw.service"], "active")
        self.assertEqual(states["ufw-vps-providers.service"], "completed")
        self.assertEqual(states["ufw-vps-providers.timer"], "active")


if __name__ == "__main__":
    unittest.main()
