"""Regression tests for the IDS security hardening changes."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd
from scapy.layers.inet import IP, TCP

import simple_ids


class EnvironmentFlagTests(unittest.TestCase):
    """Verify predictable environment-based boolean configuration."""

    def test_truthy_values_are_enabled(self):
        for value in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {"TEST_FLAG": value}):
                    self.assertTrue(simple_ids.env_flag("TEST_FLAG"))

    def test_missing_value_uses_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(simple_ids.env_flag("TEST_FLAG"))
            self.assertTrue(simple_ids.env_flag("TEST_FLAG", default=True))


class GeoIpTests(unittest.TestCase):
    """Verify invalid and non-public addresses never reach the external API."""

    def setUp(self):
        simple_ids.geoip_cache.clear()

    @mock.patch("simple_ids.requests.get")
    def test_private_ip_is_not_sent_to_geoip_provider(self, request_get):
        location = simple_ids.get_geo("192.168.1.10")

        self.assertEqual(location, "Private or reserved network")
        request_get.assert_not_called()

    @mock.patch("simple_ids.requests.get")
    def test_invalid_ip_is_rejected(self, request_get):
        self.assertEqual(simple_ids.get_geo("not-an-ip"), "Unknown")
        request_get.assert_not_called()


class FirewallTests(unittest.TestCase):
    """Verify firewall commands are validated and executed without a shell."""

    @mock.patch.object(simple_ids, "FIREWALL_BLOCKING", True)
    @mock.patch("simple_ids.os.geteuid", return_value=0)
    @mock.patch("simple_ids.subprocess.run")
    def test_ipv4_rule_uses_argument_list(self, run, _geteuid):
        run.side_effect = [
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0),
        ]

        self.assertTrue(simple_ids.block_ip_firewall("203.0.113.10"))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["iptables", "-C", "INPUT", "-s", "203.0.113.10", "-j", "DROP"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["iptables", "-A", "INPUT", "-s", "203.0.113.10", "-j", "DROP"],
        )
        self.assertNotIn("shell", run.call_args_list[1].kwargs)

    @mock.patch.object(simple_ids, "FIREWALL_BLOCKING", True)
    @mock.patch("simple_ids.subprocess.run")
    def test_invalid_ip_never_reaches_subprocess(self, run):
        self.assertFalse(simple_ids.block_ip_firewall("1.2.3.4; touch /tmp/pwned"))
        run.assert_not_called()


class EmailTests(unittest.TestCase):
    """Verify incomplete email configuration fails closed."""

    @mock.patch.object(simple_ids, "EMAIL_ALERTS", True)
    @mock.patch.object(simple_ids, "EMAIL_FROM", "")
    @mock.patch.object(simple_ids, "EMAIL_TO", "security@example.com")
    @mock.patch.object(simple_ids, "SMTP_PASS", "")
    @mock.patch("simple_ids.smtplib.SMTP")
    def test_missing_credentials_do_not_open_smtp_connection(self, smtp):
        self.assertFalse(simple_ids.send_email_alert("203.0.113.10", "Unknown"))
        smtp.assert_not_called()


class AlertLoggingTests(unittest.TestCase):
    """Verify crossing the block threshold produces one CSV row, not two."""

    def setUp(self):
        simple_ids.blocked_ips.clear()
        simple_ids.ip_port_history.clear()
        simple_ids.ip_syn_counter.clear()

    @mock.patch("simple_ids.send_email_alert")
    @mock.patch("simple_ids.block_ip_firewall")
    @mock.patch("simple_ids.get_geo", return_value="Test Location")
    def test_threshold_packet_is_logged_once(self, _geo, _firewall, _email):
        packet = IP(src="203.0.113.10") / TCP(dport=22, flags="S")

        with tempfile.TemporaryDirectory() as temp_dir:
            alert_path = Path(temp_dir) / "alerts.csv"
            with mock.patch.object(simple_ids, "ALERT_CSV", str(alert_path)):
                simple_ids.initialize_csv()
                for _ in range(simple_ids.BLOCK_THRESHOLD):
                    simple_ids.detect_suspicious_packet(packet)

                alerts = pd.read_csv(alert_path)

        self.assertEqual(len(alerts), simple_ids.BLOCK_THRESHOLD)
        self.assertEqual(bool(alerts.iloc[-1]["blocked"]), True)
        self.assertEqual(alerts.iloc[-1]["attack_type"], "SSH Brute Force")
        _firewall.assert_called_once_with("203.0.113.10")
        _email.assert_called_once_with("203.0.113.10", "Test Location")


if __name__ == "__main__":
    unittest.main()
