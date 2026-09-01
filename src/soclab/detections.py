"""Detections for common identity attacks."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from .models import Alert, AuthEvent


def _trim(window: deque[AuthEvent], current: AuthEvent, minutes: int) -> None:
    cutoff = current.timestamp - timedelta(minutes=minutes)
    while window and window[0].timestamp < cutoff:
        window.popleft()


def detect_brute_force(events: list[AuthEvent], threshold: int = 5) -> list[Alert]:
    """Detect repeated failures against one account from one IP in five minutes."""
    windows: dict[tuple[str, str], deque[AuthEvent]] = defaultdict(deque)
    emitted: set[tuple[str, str]] = set()
    alerts: list[Alert] = []
    for event in events:
        if event.outcome != "failure":
            continue
        key = (event.source_ip, event.username)
        window = windows[key]
        window.append(event)
        _trim(window, event, minutes=5)
        if len(window) >= threshold and key not in emitted:
            alerts.append(
                Alert(
                    rule_id="SOC-001",
                    title="Credential Brute Force",
                    severity="high",
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    username=event.username,
                    description=f"{len(window)} failed logins targeted one account within 5 minutes.",
                    mitre_attack=("T1110",),
                    evidence=tuple(item.timestamp.isoformat() for item in window),
                )
            )
            emitted.add(key)
    return alerts


def detect_password_spray(events: list[AuthEvent], threshold: int = 5) -> list[Alert]:
    """Detect one IP failing authentication against many users in ten minutes."""
    windows: dict[str, deque[AuthEvent]] = defaultdict(deque)
    emitted: set[str] = set()
    alerts: list[Alert] = []
    for event in events:
        if event.outcome != "failure":
            continue
        window = windows[event.source_ip]
        window.append(event)
        _trim(window, event, minutes=10)
        users = sorted({item.username for item in window})
        if len(users) >= threshold and event.source_ip not in emitted:
            alerts.append(
                Alert(
                    rule_id="SOC-002",
                    title="Password Spraying",
                    severity="high",
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    username=",".join(users),
                    description=f"Authentication failures targeted {len(users)} distinct accounts within 10 minutes.",
                    mitre_attack=("T1110.003",),
                    evidence=tuple(users),
                )
            )
            emitted.add(event.source_ip)
    return alerts


def detect_success_after_failures(events: list[AuthEvent], threshold: int = 5) -> list[Alert]:
    """Detect a successful login following repeated failures from the same IP."""
    failures: dict[tuple[str, str], deque[AuthEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    for event in events:
        key = (event.source_ip, event.username)
        window = failures[key]
        _trim(window, event, minutes=10)
        if event.outcome == "failure":
            window.append(event)
        elif event.outcome == "success" and len(window) >= threshold:
            alerts.append(
                Alert(
                    rule_id="SOC-003",
                    title="Successful Login After Repeated Failures",
                    severity="critical",
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    username=event.username,
                    description=f"A login succeeded after {len(window)} recent failures from the same source.",
                    mitre_attack=("T1110", "T1078"),
                    evidence=tuple(item.timestamp.isoformat() for item in window) + (event.timestamp.isoformat(),),
                )
            )
            window.clear()
    return alerts


def detect_foreign_admin_login(events: list[AuthEvent]) -> list[Alert]:
    """Detect successful privileged logins originating outside the expected country."""
    alerts: list[Alert] = []
    for event in events:
        if event.outcome == "success" and event.privileged and event.source_country != "US":
            alerts.append(
                Alert(
                    rule_id="SOC-004",
                    title="Foreign Privileged Account Login",
                    severity="critical",
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    username=event.username,
                    description=f"Privileged account authenticated successfully from {event.source_country}.",
                    mitre_attack=("T1078",),
                    evidence=(event.host, event.user_agent),
                )
            )
    return alerts


DETECTIONS = (
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
    detect_foreign_admin_login,
)

