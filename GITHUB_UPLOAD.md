# Publish this project on GitHub

Mac users who want complete beginner instructions should follow `MAC_SETUP.md` first.

## 1. Personalize the README

Replace both instances of `YOUR-USERNAME` in `README.md` with your exact GitHub username.

## 2. Create an empty repository

On GitHub, select **New repository** and use:

- Repository name: `soc-detection-lab`
- Description: `Python SOC detection engineering lab with Sigma-style rules and MITRE ATT&CK mapping`
- Visibility: Public
- Do not add a README, `.gitignore`, or license because the project already contains them.

## 3. Push the project

Run these commands from inside the `soc-detection-lab` folder. Replace `YOUR-USERNAME` with your username.

```bash
git init
git add .
git commit -m "Build SOC detection engineering lab"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/soc-detection-lab.git
git push -u origin main
```

## 4. Verify the portfolio presentation

- Open the **Actions** tab and confirm both test jobs pass.
- Add the repository URL to your résumé and LinkedIn projects section.
- Pin the repository on your GitHub profile.
- Review `RESUME.md` and practice explaining the detection thresholds, false positives, and incident timeline.

## Suggested GitHub topics

`cybersecurity`, `soc`, `detection-engineering`, `python`, `sigma`, `mitre-attack`, `blue-team`, `incident-response`
