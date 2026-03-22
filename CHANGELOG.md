# Changelog

All notable changes to CloudHop are documented here.

## v0.12.0

### New Features
- **Settings Page** - Centralized settings UI accessible from wizard and dashboard
- **Email Notifications** - SMTP email alerts on transfer completion and failure

## v0.11.0

### New Features
- **Sync Mode** - One-way sync (`rclone sync`) and two-way bisync (`rclone bisync`) with safety warnings for destructive operations
- **Transfer Presets** - Save, manage, and re-run transfer configurations with one click
- **Multi-Destination Transfers** - Copy one source to up to 5 cloud destinations simultaneously via queue
- **Windows .exe Installer** - Single-file standalone executable built with PyInstaller via GitHub Actions
- **Homebrew Formula** - Install with `brew tap ozymandiashh/tap && brew install cloudhop`

### Fixes
- Windows CI: ETA smoothing tests handle `os.waitpid` platform differences
- Stabilized flaky integration tests (server startup/shutdown race conditions)

## v0.9.11 (2026-03-20)

### Fixed

#### Thread safety
- **Zombie processes**: store `subprocess.Popen` object (not just PID) and use `proc.poll()` for cross-platform process liveness checks; eliminates zombie rclone processes on all platforms
- **Race condition on process state**: `rclone_pid`, `_rclone_proc`, and `transfer_active` are now always written under `state_lock` in `_resume_locked`, `_start_transfer_locked`, and CLI startup
- **Queue TOCTOU race**: `queue_process_next` no longer marks an item "running" before `start_transfer` confirms success; transient "already running" errors leave the item as "queued" for automatic retry instead of permanently marking it "failed"
- **Deadlock in queue_process_next**: fixed lock ordering violation where `state_lock` was held while calling `start_transfer` which acquires `transfer_lock`
- **load_state() and set_transfer_paths() without state_lock**: both methods now properly protect shared state mutations
- **Race condition in /api/history/resume**: state file, log file, command, and label are now swapped atomically under `state_lock`

#### Security
- **SSRF via rclone backend specifiers**: `validate_rclone_input()` now rejects values starting with `:` followed by a letter (e.g. `:http,url=http://evil.com:`), preventing Server-Side Request Forgery through rclone's on-the-fly backend syntax
- **Path traversal startswith() without os.sep**: static file serving and history resume now check `realpath.startswith(base + os.sep)` to prevent prefix-matching bypasses
- **Credential filter stripped legitimate paths**: the filter now only matches known `--flag=value` patterns (e.g. `--mega-pass=`), no longer stripping positional args that happen to contain "user" or "pass" in a path

#### Cross-platform (Windows)
- **is_rclone_running() crash on Windows**: `os.WNOHANG` does not exist on Windows; added `hasattr(os, "WNOHANG")` guard to skip `os.waitpid` and fall back to `os.kill(pid, 0)`
- **Popen interference on Windows 3.9/3.11**: `platform.system()` calls in `_resume_locked` and `_start_transfer_locked` no longer interfere with Popen kwargs assembly
- **start_new_session doesn't detach on Windows**: `cli.py` now uses `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS` creation flags on Windows instead of `start_new_session`
- **Hardcoded errno 48**: replaced with `errno.EADDRINUSE` for portable port-busy detection

#### Data integrity
- **Log truncation breaks incremental scanner**: scanner now detects when the log file is shorter than `last_scan_offset` and resets to scan from the beginning
- **_parse_recent_files/_parse_error_messages crash if log deleted**: both methods now catch `FileNotFoundError` and `PermissionError` instead of crashing

#### Stability
- **Battery resume overrides schedule pause**: `_check_battery` now checks `is_in_schedule_window()` before resuming, so a battery-paused transfer does not resume outside the schedule window
- **Background scanner logging**: replaced `print()` with `logger.exception()` so scanner errors appear in the server log file instead of being lost to stdout

### Added
- **Lock ordering documentation**: explicit rule `transfer_lock -> _scan_lock -> state_lock` documented in the `transfer.py` module docstring
- **Stress tests** (`test_stress.py`): 10 tests using real threads with 5-second deadlock detection
  - Concurrent `scan_full_log` + `parse_current` (20 threads)
  - Rapid pause/resume cycles (5 threads, 10 cycles each)
  - Concurrent queue add/remove (15 threads)
  - Concurrent state save/load (20 threads)
  - `set_transfer_paths` under contention (10 threads)
  - Mixed workload: scanner + dashboard polls + user pause + queue advance simultaneously
  - Log truncation and log growth during active scanning
  - `is_rclone_running` under contention (20 threads)
- **HTTP integration tests** (`test_server_integration.py`): 41 tests against a real HTTP server on a random port
  - All GET routes (status, wizard, queue, schedule, history, dashboard HTML, 404)
  - All POST routes with valid and invalid input
  - Security: CSRF enforcement, Host header validation, path traversal, SSRF, CORS
  - Concurrency: 20+ simultaneous requests to `/api/status`

### Changed
- **CI matrix expanded**: Python 3.10 and 3.13 added (now testing 3.9, 3.10, 3.11, 3.12, 3.13 across Ubuntu, macOS, Windows = 15 jobs)
- **CI fail-fast disabled**: all 15 matrix combinations now run to completion even if one fails
- **CI includes stress + integration tests**: same `pytest` invocation runs unit, stress, and integration tests

## v0.9.7 (2026-03-20)

### Added
- **Selective copy**: Browse button to pick source subfolder from wizard
- **Exclude folder picker**: Pick button to browse and check folders to skip
- **CLI subcommands**: `cloudhop status`, `cloudhop pause`, `cloudhop resume`, `cloudhop history`
- **Demo mode**: `/dashboard?demo=true` shows simulated transfer for preview
- **Auto-update check**: dashboard and wizard notify when a new version is available (checks GitHub Releases)
- **Error reporting**: "Report this problem" button opens pre-filled GitHub Issue
- **Need help / Send feedback** links in footer (GitHub Issues + Discussions)
- **Folder browse API**: `/api/wizard/browse` lists directories on any remote

### Fixed
- CLI subcommands now correctly obtain CSRF token from HTML page
- Browse endpoint rejects empty path
- Empty subfolder browse shows "back to root" link instead of stale content

## v0.8.0 (2026-03-20)

### Added
- **Transfer verification**: "Verify" button runs `rclone check` after completion
- **Transfer receipt**: downloadable summary of completed transfer
- **Safety banner**: "Your files are safe" message on wizard welcome
- **--fast-list option**: checkbox in wizard (default on), fewer API calls for cloud remotes
- **Milestone notifications**: browser notification + toast at 25%, 50%, 75%
- **Transfer history resume**: Resume button in history modal
- **Smart status messages**: shows "Scanning files..." or "Listing files..." instead of 0 speed
- **Sound mute toggle**: button on dashboard control bar
- **Pause on battery**: auto-pause on macOS when running on battery power
- **Crash backoff**: stops retrying after 3 failures in 5 minutes, shows helpful message
- **JS error handler**: shows friendly toast instead of silent failure
- **Completion screen**: upgraded with Verify, Receipt, and "What's next?" section
- **Enhanced history**: shows total size, file count, and last run date

### Fixed
- 19 bug fixes including: iCloud source/dest paths, bandwidth dropdown, CLI resume,
  OAuth polling race condition, AppleScript injection, version mismatch,
  schedule time validation, path traversal protection, and more

### Changed
- Wizard language simplified ("Remote" -> "Account", clearer OAuth instructions)
- Finish time display more prominent on dashboard
- Per-remote OAuth polling (no more race condition with multiple providers)

## v0.7.0 (2026-03-20)

### Added
- **Smart Scheduling**: configure time windows for transfers (e.g., 22:00-06:00)
  - Auto-pause outside the window, auto-resume when window opens
  - Day-of-week selection (weekdays, weekends, custom)
  - Per-window bandwidth limits
- **Bandwidth limiter UI**: speed limit dropdown in wizard options
- **Live bandwidth control**: change speed on the fly via rclone rc API
- **macOS notifications**: desktop alerts on transfer complete, schedule pause/resume
- **Server logging**: all events logged to `~/.cloudhop/cloudhop-server.log`
- **Schedule indicator on dashboard**: shows current schedule status with colored badge
- **Ruff linter + pre-commit hooks**: automated code quality checks on every commit

### Fixed
- Server crash on Windows when starting transfers (DETACHED_PROCESS fix)
- Server dies when terminal is closed (SIGHUP ignore)
- BrokenPipeError crashes from disconnected browser clients
- "Connection lost" message now explains what happened and how to reconnect

### Changed
- Official cloud provider logos in wizard and landing page (Google Drive, OneDrive, Dropbox, MEGA, iCloud, Proton Drive, Amazon S3)
- macOS installer is now a proper .app bundle (drag to Applications)
- CI workflow builds .app bundle with icon, creates DMG with Applications shortcut
- CI permissions fix for GitHub release uploads

## v0.6.1 (2026-03-19)

### Fixed
- Mac DMG build: retry on "Resource busy" error during hdiutil attach
- CI: bundle ARM64 rclone binary for Apple Silicon builds

## v0.6.0 (2026-03-19)

### Changed
- Rebranded from CloudMirror to CloudHop
- Open source release preparation
- Added SECURITY.md, PRIVACY.md, CONTRIBUTING.md
- Added GitHub Actions CI workflow for Mac .dmg and Windows installers
- Added dashboard screenshot to README
- PyInstaller build config for Mac .dmg

### Fixed
- Various bug fixes from rebrand and release prep

## v0.5.2 (2026-03-19)

### Fixed
- Chart rendering: axis labels, segment artifacts, files count display

## v0.5.1 (2026-03-19)

### Fixed
- Dashboard bug fixes and UI polish
- Added `--attach-pid` mode

## v0.5.0 (2026-03-19)

### Changed
- Architecture refactor: modular package structure
- Complete type hints added throughout
- 219 tests, all 5/5 PRD criteria verified

### Fixed
- 3 critical bugs from modular refactor
- TransferManager test coverage added (192 tests total)

## v0.4.0 (2026-03-19)

### Security
- CSRF protection with double-submit token pattern (SameSite=Strict cookie + X-CSRF-Token header)
- DNS rebinding protection via Host header validation
- Timing-safe CSRF comparison using `hmac.compare_digest()`
- Input validation on all API endpoints including `/api/wizard/preview`
- S3, MEGA, and Proton Drive credentials passed via environment variables (no longer visible in `ps aux`)
- Stricter exclude pattern validation (rejects glob injection characters `{}[]`)
- Transfer lock prevents TOCTOU race conditions on start/pause/resume
- XSS protection on file type extensions, preview results, and confirm modals
- State file credential filtering before persisting to disk

### Performance
- Incremental log scanning with byte offset tracking (no longer reads entire log every 30s)
- Chart history cached in state (dashboard no longer re-parses full log on every 5s poll)
- Pre-compiled regexes at module level for all hot-path parsing
- Named constants replace magic numbers throughout
- Extracted `downsample()`, `_parse_tail_stats()`, `_parse_active_transfers()`, `_parse_recent_files()`, `_parse_error_messages()` from monolithic functions
- Capped history lists at 50,000 entries to prevent unbounded memory growth
- Stats interval changed from 30s to 10s for more responsive dashboard

### Added
- Same-provider transfers (e.g., Google Drive to Google Drive with two accounts)
- Checksum verification option in wizard ("Verify with checksums" checkbox)
- Connection-lost banner when server becomes unreachable
- Graceful SIGTERM handler (transfer continues in background)
- Port auto-retry (tries ports 8787-8791 if default is busy)
- System dark/light mode auto-detection via `prefers-color-scheme`
- Live system theme change listener (follows OS dark mode toggle)
- Styled confirm/error modals replacing native `alert()`/`confirm()`

### Accessibility
- `role="dialog"` and `aria-modal="true"` on all modals
- Escape key closes modals
- Focus trap and stacking guard on modals
- `role="alert"` and `aria-live="assertive"` on connection-lost banner
- `role="status"` and `aria-live="polite"` on toast notifications
- `role="progressbar"` with dynamically updated `aria-valuenow` on progress bar
- `role="radiogroup"` and `role="radio"` with `aria-checked` on speed options
- `*:focus-visible` outline styles for keyboard navigation
- Improved color contrast (WCAG AA compliant) for `--text-muted`, `--text-dim`, `--chart-text`
- `aria-label` on theme toggles and chart SVGs

### Fixed
- Same-provider transfers now create separate rclone remotes (e.g., `gdrive` + `gdrive_dest`)
- Port retry now correctly updates global PORT (CORS origins, browser URL, printed URL all match)
- Incremental log scanner handles partial lines at seek boundaries
- `pause_rclone()` now acquires transfer lock (prevents race with resume)
- Event listener leak on "Other" provider input selection
- Hardcoded `ro-RO` locale replaced with browser default
- History modal no longer stacks on repeated clicks
- Theme toggle icons consistent between dashboard and wizard (unicode, not emoji)
- Checksum option shown in transfer summary before starting
- Connection-lost banner adjusts page padding on mobile
- State file validates `_running_*` types on load to prevent corruption

## v0.3.0 (2026-03-19)

### Added
- Progress percentage in browser tab title (`[45%] CloudHop`)
- Bandwidth limit option in wizard (e.g. 10M, 1G, 500K)
- Dry-run / Preview button on summary step (shows file count and size before starting)
- Transfer history API (`/api/history`) with link in dashboard footer
- Smoothed ETA calculation based on average speed (less fluctuation)
- Error message mapping (translates rclone errors to user-friendly messages)
- OAuth reconnect hint when token-related errors appear
- Chart cache invalidation on theme toggle (charts redraw with correct colors)

## v0.2.0 (2026-03-18)

### Added
- OAuth hint conditional (different message for browser auth vs credentials)
- Rclone installation check on Welcome page (warns before user proceeds)
- Wizard state persistence via sessionStorage (survives page refresh)
- Cancel Transfer button on dashboard (with confirmation dialog)
- Dead process detection (badge shows "Stopped" in red when rclone dies)
- Quick-select buttons for local folder paths (Desktop, Documents, Downloads)
- Auto-create destination folder if it doesn't exist

### Fixed
- Proton/MEGA/S3 credentials now save correctly (key=value format)
- Proton Drive label no longer shows as "Google Drive"
- Quick-select buttons use actual home directory (not localhost fallback)
- Quick-select buttons meet 44px touch target on mobile
- Zombie rclone size processes prevented (only one at a time)
- Dead rclone process properly detected (waitpid instead of kill)
- Empty local path shows alert instead of defaulting to "/" (read-only)

## v0.1.0 (2026-03-18)

### Features
- Web-based 6-step setup wizard with provider selection
- Real-time transfer dashboard with live-updating charts
- Supports Google Drive, OneDrive, Dropbox, MEGA, Amazon S3, Proton Drive, Local Folder
- Dark/light theme toggle with persistence
- Pause/Resume/Cancel transfers
- Session history tracking with downtime detection
- Speed, progress, and file count history charts
- Active transfer list and recent files feed
- File type breakdown
- Error tracking and display
- CLI mode for direct rclone argument passthrough
- Automatic rclone installation (macOS and Linux)
- Sound and desktop notification on transfer completion
- Single Python file, no dependencies beyond Python 3.7+

### Security
- Web server binds to localhost only (127.0.0.1)
- CORS restricted to localhost origins (strict set comparison)
- Input validation prevents rclone flag injection
- Request body size limited to 10 KB
- Credentials obscured before saving
- State files stored in ~/.cloudhop/ with 0700 permissions

### Accessibility
- Provider cards keyboard-accessible (tabindex, role, onkeydown)
- Form labels linked to inputs
- Theme toggle and all buttons meet 44px minimum touch target
- Mobile responsive (375px to 1280px)
