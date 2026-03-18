# Changelog

All notable changes to CloudMirror are documented here.

## v0.5.1-alpha (2026-03-18)

### Fixed
- Mobile dashboard overflow from long filenames in "Recently Completed"

## v0.5.0-alpha (2026-03-18)

### Fixed (MVP Blockers)
- Dashboard shows "Starting..." when rclone runs but stats not yet available (was showing "No active transfer" for first 30s)
- Validate MEGA/Proton Drive credentials after saving (rclone lsd check -- fake credentials no longer accepted)
- Sanitize raw rclone error messages to user-friendly text
- Visiting /wizard no longer resets TRANSFER_ACTIVE (was orphaning running transfers)
- Activate startPolling() for OAuth providers (was dead code, OAuth flow now works properly)
- "Starting transfer..." spinner has 30-second safety timeout recovery
- Daily chart section now visible when data exists
- Error section hides when errors are resolved

### Added
- Amazon S3 credentials UI (Access Key ID + Secret Access Key) in wizard
- Server-side guard against double-click spawning duplicate transfers
- Step validation prevents skipping wizard steps via console
- Empty "Other" remote name validation
- rclone obscure failure handling (check returncode)

### Security
- Same-provider destination click properly blocked (was CSS-only, now JS guard)

## v0.4.0-alpha (2026-03-18)

### Security
- Validate username/password inputs against rclone flag injection
- Obscure Proton Drive password via rclone obscure (was plaintext in ps aux)
- Fix CORS origin check: strict set comparison instead of substring match
- Replace pgrep with tracked PID to prevent killing unrelated rclone processes
- Validate transfers param as integer (1-64 range)
- Move state/log files from /tmp to ~/.cloudmirror/ with 0700 permissions
- Expand credential stripping filter for saved state
- Add do_OPTIONS handler for CORS preflight

### Accessibility
- All 16 provider cards keyboard-accessible (tabindex, role, onkeydown)
- Form labels linked to inputs via for attribute

### Fixed
- Dashboard header overflow at 375px mobile (flex-wrap)
- iOS auto-zoom on form inputs (font-size 1rem)
- Toast, stat-card hover, error item colors use CSS variables (light mode fix)
- Chart empty state text contrast improved
- AudioContext leak fixed (reuse single cached instance)
- Favicon canvas cached, skip redraw when unchanged
- Polling interval slows to 30s after transfer completes
- Notification.requestPermission moved to user gesture

### Added
- Empty state overlay on dashboard ("No active transfer" with action button)
- "Already selected as source" text on disabled destination cards
- Reassurance text: "Your originals will stay untouched"
- OAuth instruction on connect step
- Port-already-in-use handled gracefully
- Windows platform compatibility notice
- Improved "Other" provider hint with examples

## v0.3.0-alpha (2026-03-18)

### Security
- Bind web server to localhost (127.0.0.1) only -- not accessible from LAN
- Input validation rejects rclone flag injection via `--` or `-` prefixed values
- XSS protection: all user-supplied content is JSON-serialized, not injected into HTML
- CORS restricted to localhost/127.0.0.1 origins
- Request body size limited to 10 KB

### Added
- "New Transfer" button on dashboard to return to wizard
- Same-provider warning when source and destination use the same service

### Fixed
- MEGA provider credential handling in wizard
- Local Folder and Other (advanced) provider options now work in wizard
- Theme toggle properly redraws speed/progress charts
- Firefox scrollbar rendering artifact

### Improved
- Dark mode contrast and readability
- Dashboard empty state shows helpful message instead of blank
- Pre-compiled regex patterns for log parsing performance
- Credential-containing flags stripped from saved state

### Removed
- Dead CLI wizard code (replaced by web wizard)

## v0.2.0-alpha (2026-03-18)

### Fixed
- 29 bugs identified in comprehensive audit
- Resume tracking now persists state to JSON across restarts
- Total bytes calculation uses first session total as baseline
- Session boundary detection uses elapsed time drop heuristic

### Added
- SVG provider logos in wizard
- File type breakdown chart on dashboard

### Improved
- Log parsing robustness with error-tolerant decoding

## v0.1.0-alpha (2026-03-18)

### Added
- Initial release
- Web-based 6-step setup wizard with provider selection
- Real-time transfer dashboard with live-updating charts
- Dark/light theme toggle
- Session history tracking with downtime detection
- Speed, progress, and file count history charts
- Active transfer list and recent files feed
- Error tracking and display
- CLI mode for direct rclone argument passthrough
- Automatic rclone installation (macOS and Linux)
- Sound notification on transfer completion
