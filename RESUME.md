# Résumé and interview language

## Project title

**SOC Detection Engineering Lab | Python, Sigma, MITRE ATT&CK, GitHub Actions**

## Résumé bullets

- Engineered a Python-based SOC detection pipeline that normalized authentication telemetry and identified brute force, password spraying, post-failure account access, and anomalous privileged logins.
- Authored four Sigma detection/correlation rule files mapped to MITRE ATT&CK techniques T1110, T1110.003, and T1078; generated structured alerts and a standalone analyst dashboard.
- Built automated unit tests and a GitHub Actions CI workflow, then documented triage, containment, false-positive considerations, and incident findings using a fully reproducible synthetic dataset.

## 30-second interview explanation

“I built this project to demonstrate the full detection lifecycle rather than only writing a script. It ingests and normalizes authentication logs, correlates activity over time, creates alerts for common identity attacks, and maps them to MITRE ATT&CK. I also wrote Sigma detection and correlation rules, automated tests, CI, a dashboard, and an incident report. The sample data is synthetic, so the entire project is safe and reproducible on GitHub.”

## Accuracy note

Use these bullets after you have run the project, reviewed the code, and can explain each detection and its limitations in your own words.
