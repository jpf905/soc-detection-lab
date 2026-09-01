# Mac Setup Guide — Start Here

This guide assumes you are new to running a Python project locally. Complete the steps in order. You only need to install Python and Git once.

## Part 1: Put the project on your Mac

1. Download `soc-detection-lab.zip`.
2. Open **Finder**, then open **Downloads**.
3. Double-click `soc-detection-lab.zip`. Your Mac will create a folder named `soc-detection-lab`.
4. In **Documents**, create a folder named `Cybersecurity-Portfolio`.
5. Move the entire `soc-detection-lab` folder into `Cybersecurity-Portfolio`.

Your folder should now be located approximately here:

```text
Documents/Cybersecurity-Portfolio/soc-detection-lab
```

Do not move the individual files out of `soc-detection-lab`. The folder structure is part of the project.

## Part 2: Install and verify Python

The project requires Python 3.10 or newer.

1. Open [python.org/downloads/macos](https://www.python.org/downloads/macos/).
2. Download the current **macOS 64-bit universal2 installer**.
3. Open the downloaded `.pkg` file and follow the installation prompts.
4. Open **Terminal**. Press **Command + Space**, type `Terminal`, and press **Return**.
5. Enter the following command and press **Return**:

```bash
python3 --version
```

You should see `Python 3.10` or a newer version. A newer version such as 3.12, 3.13, or 3.14 is acceptable.

## Part 3: Install and verify Git

In Terminal, enter:

```bash
git --version
```

If Git is already installed, its version will appear. If your Mac asks to install command-line developer tools, select **Install**, wait for the installation to finish, and run `git --version` again.

## Part 4: Open the project folder in Terminal

This drag-and-drop method prevents typing the folder path incorrectly:

1. In Terminal, type `cd` followed by one space. Do not press Return yet.
2. In Finder, locate the `soc-detection-lab` folder.
3. Drag that folder into the Terminal window. Terminal will insert its full path.
4. Press **Return**.
5. Enter `pwd` and press **Return**. The displayed path should end with `/soc-detection-lab`.

## Part 5: Create the project environment

Run each command separately. Wait for each command to finish before entering the next one.

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

Your Terminal prompt should now begin with `(.venv)`. Install the project and its validation tool:

```bash
python3 -m pip install --upgrade pip
```

```bash
python3 -m pip install -e ".[dev]"
```

## Part 6: Test the project

Run the automated Python tests:

```bash
python3 -m unittest discover -s tests -v
```

The final result should say:

```text
Ran 7 tests
OK
```

Validate the Sigma detection rules:

```bash
sigma check rules
```

The summary should report zero errors, zero condition errors, and zero issues.

## Part 7: Run the SOC analysis

Enter:

```bash
soclab --input data/sample_auth_logs.csv --output output
```

The summary should report 20 events and four alerts. Open the dashboard:

```bash
open output/dashboard.html
```

The dashboard will open in your default browser. The machine-readable alerts are saved in `output/alerts.json`.

When you finish working, deactivate the project environment:

```bash
deactivate
```

The next time you return to the project, open Terminal in the project folder and run `source .venv/bin/activate` before using `soclab`.

## Part 8: Personalize the repository

1. Open `README.md` with a plain-text editor.
2. Replace both instances of `YOUR-USERNAME` with your exact GitHub username.
3. Save the file without changing its `.md` extension.

If you use TextEdit, choose **Format > Make Plain Text** before saving. Do not save the file as `.rtf`.

## Part 9: Prepare the Git repository

In Terminal, make sure you are inside `soc-detection-lab`, then run:

```bash
git init
```

Configure the name attached to your commits:

```bash
git config --global user.name "John Flanagan"
```

Configure the email associated with your GitHub account. Replace the example with your actual email:

```bash
git config --global user.email "YOUR-GITHUB-EMAIL"
```

Create the first commit:

```bash
git add .
```

```bash
git commit -m "Build SOC detection engineering lab"
```

```bash
git branch -M main
```

## Part 10: Publish with GitHub Desktop — easiest method

1. Install [GitHub Desktop for macOS](https://desktop.github.com/download/).
2. Open GitHub Desktop and sign in to your GitHub account.
3. Select **File > Add Local Repository**.
4. Select the `soc-detection-lab` folder and click **Add Repository**.
5. Click **Publish repository**.
6. Confirm the name is `soc-detection-lab`.
7. Use this description: `Python SOC detection engineering lab with Sigma rules and MITRE ATT&CK mapping`.
8. Clear **Keep this code private** so recruiters can view it.
9. Click **Publish Repository**.

After publishing, open the repository on GitHub. Select the **Actions** tab and confirm the test workflow finishes with green check marks.

## Part 11: Finish the portfolio presentation

- Add these GitHub topics: `cybersecurity`, `soc`, `detection-engineering`, `python`, `sigma`, `mitre-attack`, `blue-team`, `incident-response`.
- Pin the project on your GitHub profile.
- Add the repository link to your résumé and LinkedIn profile.
- Read `RESUME.md` before copying the résumé bullets.
- Practice explaining each alert and the incident timeline in `docs/incident-report.md`.

## Troubleshooting

### `command not found: python3`

Python did not install correctly or Terminal was open during installation. Close Terminal, reopen it, and run `python3 --version`. If it still fails, reinstall Python from python.org.

### `command not found: soclab`

Activate the environment and try again:

```bash
source .venv/bin/activate
```

### `No such file or directory`

You are probably in the wrong folder. Repeat Part 4 and drag the complete `soc-detection-lab` folder into Terminal after typing `cd `.

### Git asks who you are

Run the `git config` name and email commands in Part 9, then repeat the commit.

### The GitHub Actions badge says repository not found

Make sure every `YOUR-USERNAME` placeholder in `README.md` was replaced with your exact, case-sensitive GitHub username.

