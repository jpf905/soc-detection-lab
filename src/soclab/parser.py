"""CSV ingestion and normalization."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from .models import AuthEvent


REQUIRED_FIELDS = {
    "timestamp",
    "event_type",
    "username",
    "source_ip",
    "source_country",
    "outcome",
    "privileged",
    "host",
    "user_agent",
}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_auth_events(path: str | Path) -> list[AuthEvent]:
    """Load, validate, normalize, and chronologically sort CSV events."""
    events: list[AuthEvent] = []
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_FIELDS.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            outcome = row["outcome"].strip().lower()
            if outcome not in {"success", "failure"}:
                raise ValueError(f"Row {row_number}: invalid outcome '{outcome}'")
            events.append(
                AuthEvent(
                    timestamp=parse_timestamp(row["timestamp"].strip()),
                    event_type=row["event_type"].strip().lower(),
                    username=row["username"].strip().lower(),
                    source_ip=row["source_ip"].strip(),
                    source_country=row["source_country"].strip().upper(),
                    outcome=outcome,
                    privileged=row["privileged"].strip().lower() in {"true", "1", "yes"},
                    host=row["host"].strip().lower(),
                    user_agent=row["user_agent"].strip(),
                )
            )
    return sorted(events, key=lambda event: event.timestamp)

