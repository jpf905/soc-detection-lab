from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from soclab.detections import (
    detect_brute_force,
    detect_foreign_admin_login,
    detect_password_spray,
    detect_success_after_failures,
)
from soclab.models import AuthEvent
from soclab.engine import analyze
from soclab.parser import load_auth_events


BASE = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


def event(minute: float, username: str = "alice", ip: str = "203.0.113.5", outcome: str = "failure", country: str = "US", privileged: bool = False) -> AuthEvent:
    return AuthEvent(BASE + timedelta(minutes=minute), "login", username, ip, country, outcome, privileged, "vpn-01", "test-agent")


class DetectionTests(unittest.TestCase):
    def test_brute_force_requires_threshold_within_window(self):
        events = [event(i) for i in range(5)]
        self.assertEqual(len(detect_brute_force(events)), 1)
        self.assertEqual(detect_brute_force(events)[0].rule_id, "SOC-001")

    def test_brute_force_does_not_combine_accounts(self):
        events = [event(i, username=f"user{i}") for i in range(5)]
        self.assertEqual(detect_brute_force(events), [])

    def test_password_spray_counts_distinct_accounts(self):
        events = [event(i, username=f"user{i}") for i in range(5)]
        self.assertEqual(len(detect_password_spray(events)), 1)

    def test_success_after_failures(self):
        events = [event(i) for i in range(5)] + [event(5, outcome="success")]
        alerts = detect_success_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "critical")

    def test_foreign_admin_login(self):
        events = [event(0, outcome="success", country="DE", privileged=True)]
        self.assertEqual(len(detect_foreign_admin_login(events)), 1)

    def test_expected_country_admin_does_not_alert(self):
        events = [event(0, outcome="success", country="US", privileged=True)]
        self.assertEqual(detect_foreign_admin_login(events), [])

    def test_sample_dataset_generates_expected_alerts(self):
        data_path = Path(__file__).parents[1] / "data" / "sample_auth_logs.csv"
        alerts = analyze(load_auth_events(data_path))
        self.assertEqual([alert.rule_id for alert in alerts], ["SOC-001", "SOC-003", "SOC-002", "SOC-004"])


if __name__ == "__main__":
    unittest.main()
