# CloudMirror v0.6.0 - Open Source Release

**Date:** 2026-03-19
**Status:** Approved
**Goal:** Make CloudMirror downloadable by anyone (non-technical users included) and enable donations.

---

## Product Identity

**Name:** CloudMirror - Free Cloud File Transfer
**License:** MIT (open source, free forever)
**Monetization:** Donations only (GitHub Sponsors + Ko-fi). No paid features, no freemium.

---

## Distribution

| Platform | Format | Source |
|---|---|---|
| macOS | `.dmg` with app bundle (PyInstaller) | GitHub Releases |
| Windows | `.exe` installer (PyInstaller) | GitHub Releases |
| Linux / Developers | `pip install cloudmirror` | PyPI |
| Source | `git clone` / download ZIP | GitHub |

No code signing at launch. Add if Apple/Windows gatekeeper requires it.

---

## README Redesign

Structure:
1. Hero: product name + tagline + dashboard screenshot
2. Download buttons: Mac / Windows / pip (big, prominent)
3. Demo GIF: 30-second wizard walkthrough
4. Features: 5-6 bullet points with icons
5. Supported providers: logo strip (Google Drive, OneDrive, Dropbox, MEGA, S3, Proton Drive, Local)
6. Install instructions: tabbed per platform
7. Screenshots: wizard + dashboard (dark mode)
8. Donate / Sponsor section

---

## Bug Fixes (included in v0.6.0)

1. **files_history backend** - cumulative file count inflated 300x across 50 sessions. Fix the offset calculation in transfer.py scan_full_log.
2. **Session counting** - false session boundaries creating 50 sessions from one transfer. Review MIN_SESSION_ELAPSED_SEC and elapsed drop detection.
3. **Chart rendering** - segment artifacts already fixed in v0.5.2 (frontend). Backend fix needed.

---

## Monetization Setup

- Enable GitHub Sponsors on the repo
- Create Ko-fi or Buy Me a Coffee account
- Add sponsor/donate links to: README, dashboard footer, wizard completion page

---

## What We Are NOT Building (YAGNI)

- Multi-transfer / queue system
- Email or webhook notifications
- Remote folder browser (rclone lsd integration)
- Code-signed installers (unless platform requires it)
- Separate landing page / website
- Auto-update mechanism
- Localization / translations
- Plugin system

---

## Success Criteria

- `pip install cloudmirror && cloudmirror` works on a clean machine with Python 3.9+
- Mac .dmg: double-click installs, launches wizard in browser
- Windows .exe: double-click installs, launches wizard in browser
- GitHub README has download buttons, screenshots, demo GIF
- GitHub Sponsors or Ko-fi link is live
- Zero known bugs at release
