# Incident Report: Suspected Credential Compromise

**Case ID:** IR-2026-0820-01  
**Status:** Contained (simulated)  
**Severity:** Critical  
**Data classification:** Synthetic training data

## Executive summary

The detection engine identified repeated authentication failures against `jdoe` from `203.0.113.50`, followed by a successful login. The source was geolocated to a country outside the expected operating region. This sequence is consistent with a successful brute-force attempt or use of compromised credentials.

## Detection timeline

| UTC time | Observation |
| --- | --- |
| 12:10:00–12:12:20 | Five failed login attempts targeted `jdoe` from `203.0.113.50`. |
| 12:12:20 | Rule SOC-001 generated a high-severity brute-force alert. |
| 12:13:00 | Authentication succeeded from the same source and account. |
| 12:13:00 | Rule SOC-003 generated a critical alert for success after repeated failures. |

## MITRE ATT&CK mapping

- T1110 — Brute Force
- T1078 — Valid Accounts

## Analyst assessment

The temporal relationship between repeated failures and the subsequent success raises the likelihood of account compromise. The unusual source geography and automated user agent increase confidence. No production systems or real user records were involved in this laboratory scenario.

## Recommended containment

1. Disable active sessions and temporarily lock the affected account.
2. Force a password reset and verify multifactor-authentication enrollment.
3. Block the source IP at the identity provider or perimeter control.
4. Review downstream activity for mailbox rules, privilege changes, persistence, and lateral movement.
5. Preserve authentication and endpoint telemetry for the investigation.

## Lessons learned

- Correlating successful and failed events creates a stronger signal than monitoring failures alone.
- Identity detections require allowlists for approved VPN ranges and administrator travel.
- Production deployment should tune thresholds against historical baselines and measure false positives.

