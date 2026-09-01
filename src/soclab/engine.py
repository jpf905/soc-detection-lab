"""Detection orchestration."""

from __future__ import annotations

from .detections import DETECTIONS
from .models import Alert, AuthEvent


def analyze(events: list[AuthEvent]) -> list[Alert]:
    alerts = [alert for detection in DETECTIONS for alert in detection(events)]
    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule_id))

