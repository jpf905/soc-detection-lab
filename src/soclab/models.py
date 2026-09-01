"""Data models for normalized events and alerts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    event_type: str
    username: str
    source_ip: str
    source_country: str
    outcome: str
    privileged: bool
    host: str
    user_agent: str


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    timestamp: datetime
    source_ip: str
    username: str
    description: str
    mitre_attack: tuple[str, ...]
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        data["mitre_attack"] = list(self.mitre_attack)
        data["evidence"] = list(self.evidence)
        return data

