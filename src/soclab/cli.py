"""Command-line interface."""

from __future__ import annotations

import argparse
from pathlib import Path

from .engine import analyze
from .parser import load_auth_events
from .report import write_html, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze authentication telemetry for suspicious activity.")
    parser.add_argument("--input", default="data/sample_auth_logs.csv", help="CSV telemetry path")
    parser.add_argument("--output", default="output", help="Output directory")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    events = load_auth_events(args.input)
    alerts = analyze(events)
    output = Path(args.output)
    write_json(alerts, output / "alerts.json")
    write_html(events, alerts, output / "dashboard.html")
    print(f"Analyzed {len(events)} events and generated {len(alerts)} alerts.")
    for alert in alerts:
        print(f"[{alert.severity.upper():8}] {alert.rule_id} {alert.title} | {alert.source_ip} | {alert.username}")
    print(f"Reports written to {output.resolve()}")


if __name__ == "__main__":
    main()

