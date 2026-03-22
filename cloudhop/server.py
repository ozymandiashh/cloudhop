"""CloudHop HTTP server.

Routes overview
---------------
GET  /                        Redirect: dashboard if transfer is active, wizard otherwise
GET  /dashboard               Transfer monitoring UI
GET  /wizard                  Setup wizard UI
GET  /api/status              Live transfer stats (polled every 5 s by dashboard.js)
GET  /api/wizard/status       rclone install check + list of existing remotes
GET  /api/history             List of past transfer state files from ~/.cloudhop/
GET  /static/<file>           Serves CSS/JS from the package ``static/`` directory

POST /api/pause               Kill the rclone process (pause = kill; resume = restart)
POST /api/resume              Restart rclone using the last saved command
POST /api/wizard/check-rclone Check whether rclone is installed
POST /api/wizard/install-rclone Install rclone non-interactively if missing
POST /api/wizard/configure-remote  Create an rclone remote (OAuth or credentials)
POST /api/wizard/check-remote      Poll whether a remote is now configured (OAuth flow)
POST /api/wizard/preview      Run ``rclone size`` to estimate transfer scope
POST /api/wizard/start        Validate inputs, build rclone command, launch subprocess
POST /api/wizard/start-multi-dest  Copy one source to multiple destinations via queue

Security model
--------------
- Server binds to ``127.0.0.1`` only, so it is never reachable from the network.
- ``_check_host`` rejects any request whose ``Host`` header is not
  ``localhost`` or ``127.0.0.1``, blocking DNS-rebinding attacks.
- Every mutating POST endpoint requires the ``X-CSRF-Token`` header to match
  a random token that was set as a ``SameSite=Strict`` cookie on page load.
  ``hmac.compare_digest`` is used to prevent timing attacks.
- CORS is restricted to the exact localhost origin so malicious pages on
  other ports cannot make cross-origin requests.
- Static files are served with a directory-traversal check (``os.path.realpath``).
"""

import http.server
import json
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, Optional

from . import __version__

logger = logging.getLogger("cloudhop.server")

# Serialises concurrent rclone config create calls (e.g. two browser tabs).
_configure_lock = threading.Lock()

from .presets import (
    delete_preset,
    get_preset,
    list_presets,
    run_preset,
    save_preset,
)
from .settings import load_settings, save_settings
from .templates import render
from .transfer import (
    TransferManager,
    find_rclone,
    get_existing_remotes,
    remote_exists,
    validate_rclone_cmd,
)
from .utils import (
    _CM_DIR,
    MAX_REQUEST_BODY_BYTES,
    PORT,
    RCLONE_PREVIEW_TIMEOUT_SEC,
    SYSTEM_EXCLUDES,
    TRANSFER_LABEL,
    validate_rclone_input,
)

_csrf_tokens: Dict[str, float] = {}  # {token_str: expiry_timestamp}
_csrf_lock = threading.Lock()
CSRF_TOKEN_LIFETIME = 86400  # 24 hours
_MAX_CSRF_TOKENS = 100

_PROVIDER_SPEEDS_MBS = {
    "local": 100,
    "sftp": 100,
    "drive": 10,
    "onedrive": 10,
    "protondrive": 3,
    "s3": 20,
    "b2": 20,
}


def _estimate_duration(
    size_bytes: int, source_type: str, dest_type: str, bw_limit_str: str
) -> tuple:
    """Return (human_string, seconds, speed_bytes_per_sec) estimate."""
    if bw_limit_str:
        try:
            bw_val = float(re.sub(r"[^0-9.]", "", bw_limit_str))
            speed_est = bw_val * 1024 * 1024
        except (ValueError, TypeError):
            speed_est = 10 * 1024 * 1024
    else:
        src_mbs = _PROVIDER_SPEEDS_MBS.get(source_type, 10)
        dst_mbs = _PROVIDER_SPEEDS_MBS.get(dest_type, 10)
        speed_est = min(src_mbs, dst_mbs) * 1024 * 1024
    est_sec = size_bytes / speed_est if speed_est > 0 else 0
    if est_sec < 60:
        est_dur = "less than a minute"
    elif est_sec < 3600:
        est_dur = f"~{int(est_sec / 60)} minutes"
    elif est_sec < 86400:
        eh = int(est_sec / 3600)
        em = int((est_sec % 3600) / 60)
        est_dur = f"~{eh} hour{'s' if eh != 1 else ''}"
        if em > 0:
            est_dur += f" {em} minutes"
    else:
        ed = int(est_sec / 86400)
        eh = int((est_sec % 86400) / 3600)
        est_dur = f"~{ed} day{'s' if ed != 1 else ''}"
        if eh > 0:
            est_dur += f" {eh} hour{'s' if eh != 1 else ''}"
    return est_dur, int(est_sec), speed_est


def generate_csrf_token() -> str:
    """Generate a new CSRF token, store it with expiry, and clean up stale tokens."""
    token = secrets.token_hex(32)
    now = time.time()
    with _csrf_lock:
        # Cleanup expired tokens
        expired = [t for t, exp in _csrf_tokens.items() if exp < now]
        for t in expired:
            del _csrf_tokens[t]
        # FIFO cleanup if too many
        while len(_csrf_tokens) >= _MAX_CSRF_TOKENS:
            oldest = min(_csrf_tokens, key=_csrf_tokens.get)
            del _csrf_tokens[oldest]
        _csrf_tokens[token] = now + CSRF_TOKEN_LIFETIME
    return token


# Initial token (also used by tests that import CSRF_TOKEN directly).
CSRF_TOKEN = generate_csrf_token()


class CloudHopHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for CloudHop."""

    # Class-level reference to the TransferManager instance.
    # Must be set before starting the server.
    manager: Optional[TransferManager] = None
    # Actual port the server is listening on (set by cli.py after bind).
    actual_port: int = PORT

    # ── Response helpers ────────────────────────────────────────────────

    def _send_json(self, data: Dict[str, Any], status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        # Only allow CORS from localhost to prevent cross-site request forgery
        # from malicious pages that might try to start transfers.
        origin = self.headers.get("Origin", "")
        port = self.actual_port
        allowed_origins = {f"http://localhost:{port}", f"http://127.0.0.1:{port}"}
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self, html: str) -> None:
        csrf_token = generate_csrf_token()
        html = html.replace("__VERSION__", __version__)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"csrf_token={csrf_token}; Path=/; SameSite=Strict")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
        )
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_404(self) -> None:
        """Return an animated 404 HTML page with a confused cloud character."""
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<!DOCTYPE html><html lang='en'><head>"
            b"<meta charset='UTF-8'>"
            b"<meta name='viewport' content='width=device-width,initial-scale=1.0'>"
            b"<title>404 - CloudHop</title>"
            b"<style>"
            b"*{margin:0;padding:0;box-sizing:border-box}"
            b"body{min-height:100vh;background:#0d0d1a;"
            b"font-family:-apple-system,sans-serif;"
            b"display:flex;flex-direction:column;align-items:center;"
            b"justify-content:center;color:#e0e0f0}"
            b".cc{position:relative;margin-bottom:2rem}"
            b".cb{width:180px;height:90px;"
            b"background:linear-gradient(135deg,#2a2a4a,#1e1e3a);"
            b"border-radius:90px;position:relative;"
            b"animation:confused 2s ease-in-out infinite}"
            b".cb::before{content:'';position:absolute;width:70px;height:70px;"
            b"background:linear-gradient(135deg,#2a2a4a,#1e1e3a);"
            b"border-radius:50%;top:-35px;left:25px}"
            b".cb::after{content:'';position:absolute;width:90px;height:80px;"
            b"background:linear-gradient(135deg,#2a2a4a,#1e1e3a);"
            b"border-radius:50%;top:-40px;left:65px}"
            b"@keyframes confused{0%,100%{transform:rotate(0)}25%{transform:rotate(3deg)}"
            b"75%{transform:rotate(-3deg)}}"
            b".eyes{position:absolute;top:20px;left:50%;transform:translateX(-50%);"
            b"display:flex;gap:25px;z-index:5}"
            b".eye{width:22px;height:22px;background:#fff;border-radius:50%;"
            b"position:relative;overflow:hidden}"
            b".pupil{width:10px;height:10px;background:#1a1a2e;border-radius:50%;"
            b"position:absolute;top:6px;left:6px;animation:look 3s ease-in-out infinite}"
            b"@keyframes look{0%,100%{top:6px;left:6px}20%{top:4px;left:10px}"
            b"40%{top:8px;left:10px}60%{top:8px;left:2px}80%{top:4px;left:2px}}"
            b".mouth{position:absolute;top:48px;left:50%;transform:translateX(-50%);"
            b"width:30px;height:15px;border:3px solid #888;border-top:none;"
            b"border-radius:0 0 15px 15px;z-index:5;animation:mm 3s ease-in-out infinite}"
            b"@keyframes mm{0%,100%{width:30px}50%{width:20px}}"
            b".qm{position:absolute;top:-50px;right:-20px;z-index:5}"
            b".q{font-size:1.5rem;color:#6C63FF;font-weight:900;"
            b"animation:qp 2s ease-in-out infinite;display:inline-block}"
            b".q:nth-child(1){animation-delay:0s;font-size:1.2rem}"
            b".q:nth-child(2){animation-delay:.3s;font-size:1.8rem}"
            b".q:nth-child(3){animation-delay:.6s;font-size:1rem}"
            b"@keyframes qp{0%,100%{opacity:.3;transform:translateY(0)}"
            b"50%{opacity:1;transform:translateY(-10px)}}"
            b".sw{position:absolute;top:10px;left:15px;font-size:1rem;"
            b"animation:sd 2s ease-in infinite;z-index:5}"
            b"@keyframes sd{0%{opacity:.8;transform:translate(0,0)}"
            b"100%{opacity:0;transform:translate(-5px,20px)}}"
            b".ct{text-align:center}"
            b".ec{font-size:7rem;font-weight:900;color:#6C63FF;line-height:1;"
            b"margin-bottom:.5rem;text-shadow:0 0 40px rgba(108,99,255,.3)}"
            b".msg{font-size:1.3rem;font-weight:700;margin-bottom:.3rem}"
            b".sub{color:#555570;font-size:.9rem;margin-bottom:2.5rem;max-width:360px}"
            b".btn{padding:14px 36px;background:#6C63FF;color:#fff;border:none;"
            b"border-radius:50px;font-family:-apple-system,sans-serif;"
            b"font-size:1rem;font-weight:700;cursor:pointer;text-decoration:none;"
            b"transition:all .3s;box-shadow:0 4px 20px rgba(108,99,255,.4)}"
            b".btn:hover{transform:scale(1.05);box-shadow:0 6px 30px rgba(108,99,255,.6)}"
            b"</style></head><body>"
            b"<div class='cc'><div class='cb'>"
            b"<div class='eyes'><div class='eye'><div class='pupil'></div></div>"
            b"<div class='eye'><div class='pupil'></div></div></div>"
            b"<div class='mouth'></div></div>"
            b"<div class='qm'><span class='q'>?</span><span class='q'>?</span>"
            b"<span class='q'>?</span></div>"
            b"<div class='sw'>&#x1F4A7;</div></div>"
            b"<div class='ct'><div class='ec'>404</div>"
            b"<p class='msg'>Even the cloud is confused.</p>"
            b"<p class='sub'>We asked every server. They all said "
            b"&quot;never heard of it.&quot; This is awkward.</p>"
            b"<a href='/' class='btn'>Help the cloud find its way</a>"
            b"</div></body></html>"
        )

    def _serve_static(self, filename: str) -> None:
        """Serve static CSS/JS files."""
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        # Prevent directory traversal by resolving the real path and ensuring
        # it stays within the static directory.
        filepath = os.path.realpath(os.path.join(static_dir, filename))
        if not filepath.startswith(os.path.realpath(static_dir) + os.sep):
            self.send_response(403)
            self.end_headers()
            return
        if not os.path.exists(filepath):
            self._send_404()
            return
        ext = filename.rsplit(".", 1)[-1]
        content_types = {"css": "text/css", "js": "application/javascript", "svg": "image/svg+xml"}
        self.send_response(200)
        self.send_header("Content-Type", content_types.get(ext, "text/plain"))
        size = os.path.getsize(filepath)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        with open(filepath, "rb") as f:
            self.wfile.write(f.read())

    # ── Security checks ─────────────────────────────────────────────────

    def _check_csrf(self) -> bool:
        """Verify CSRF token from X-CSRF-Token header exists in active token store."""
        token = self.headers.get("X-CSRF-Token")
        if not token:
            self._send_json({"ok": False, "msg": "CSRF token invalid"}, 403)
            return False
        with _csrf_lock:
            expiry = _csrf_tokens.get(token)
            if expiry is None:
                self._send_json({"ok": False, "msg": "CSRF token invalid"}, 403)
                return False
            if time.time() > expiry:
                del _csrf_tokens[token]
                self._send_json({"ok": False, "msg": "CSRF token invalid"}, 403)
                return False
        return True

    def _check_host(self) -> bool:
        """Reject requests where Host header is not localhost/127.0.0.1."""
        host = self.headers.get("Host", "")
        host_name = host.split(":")[0]
        if host_name not in ("localhost", "127.0.0.1"):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Forbidden: invalid Host header")
            return False
        return True

    def _read_body(self) -> Optional[Dict[str, Any]]:
        """Read and parse the JSON request body with a size cap."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            return None
        if length < 0:
            return None
        if length > MAX_REQUEST_BODY_BYTES:
            return None
        if length > 0:
            try:
                parsed = json.loads(self.rfile.read(length))
                if not isinstance(parsed, dict):
                    return None
                return parsed
            except (json.JSONDecodeError, ValueError):
                return None
        return {}

    # ── GET routes ───────────────────────────────────────────────────────

    def do_GET(self) -> None:
        if not self._check_host():
            return
        if self.manager is None:
            self._send_json({"ok": False, "msg": "Server not ready"}, 503)
            return

        # Strip query string for route matching
        path = self.path.split("?")[0]

        port = self.actual_port

        if path == "/api/status":
            self._send_json(self.manager.parse_current())
        elif path == "/api/check-update":
            from . import __version__

            try:
                import urllib.request

                req = urllib.request.Request(
                    "https://api.github.com/repos/ozymandiashh/cloudhop/releases/latest",
                    headers={"Accept": "application/vnd.github+json"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())
                tag = data.get("tag_name", "")
                latest = tag.lstrip("v") if tag else __version__
                is_app = getattr(sys, "_MEIPASS", None) is not None

                def _parse_version(v: str) -> tuple:
                    """Parse '0.12.0' into (0, 12, 0) for semantic comparison."""
                    try:
                        return tuple(int(x) for x in v.split("."))
                    except (ValueError, AttributeError):
                        return (0,)

                update_available = _parse_version(latest) > _parse_version(__version__)
                logger.info(
                    "[F305] Version check: current=%s, remote=%s, update=%s",
                    __version__,
                    latest,
                    update_available,
                )
                self._send_json(
                    {
                        "current": __version__,
                        "latest": latest,
                        "update_available": update_available,
                        "download_url": data.get("html_url", ""),
                        "pip_command": "" if is_app else "pip install --upgrade cloudhop",
                    }
                )
            except Exception:
                self._send_json(
                    {
                        "current": __version__,
                        "latest": __version__,
                        "update_available": False,
                    }
                )
        elif path == "/api/wizard/status":
            self._send_json(
                {
                    "rclone_installed": find_rclone() is not None,
                    "remotes": get_existing_remotes(),
                    "home_dir": os.path.expanduser("~"),
                }
            )
        elif path == "/api/error-log":
            from . import __version__

            home = os.path.expanduser("~")
            lines = []
            if os.path.exists(self.manager.log_file):
                try:
                    with open(self.manager.log_file, "rb") as f:
                        f.seek(0, 2)
                        fsize = f.tell()
                        f.seek(max(0, fsize - 200000))
                        tail = f.read().decode("utf-8", errors="replace")
                    for line in tail.split("\n"):
                        if "ERROR" in line:
                            lines.append(line.replace(home, "~"))
                except Exception:
                    pass
            server_log = os.path.join(_CM_DIR, "cloudhop-server.log")
            if os.path.exists(server_log):
                try:
                    with open(server_log, "rb") as f:
                        f.seek(0, 2)
                        fsize = f.tell()
                        f.seek(max(0, fsize - 50000))
                        tail = f.read().decode("utf-8", errors="replace")
                    for line in tail.split("\n"):
                        if "ERROR" in line or "Traceback" in line:
                            lines.append(line.replace(home, "~"))
                except Exception:
                    pass
            import platform as _platform

            self._send_json(
                {
                    "version": __version__,
                    "platform": f"{_platform.system()} {_platform.release()}",
                    "python": _platform.python_version(),
                    "errors": lines[-50:],
                }
            )
        elif path == "/api/queue":
            self._send_json({"queue": self.manager.queue_list()})
        elif path == "/api/schedule":
            with self.manager.state_lock:
                schedule = dict(self.manager.state.get("schedule", {}))
            if hasattr(self.manager, "is_in_schedule_window"):
                schedule["in_window"] = self.manager.is_in_schedule_window()
            else:
                schedule["in_window"] = True
            self._send_json(schedule)
        elif path == "/api/history":
            from .utils import fmt_bytes

            history = []
            for f in sorted(os.listdir(_CM_DIR)):
                if f.endswith("_state.json"):
                    try:
                        with open(os.path.join(_CM_DIR, f)) as sf:
                            s = json.load(sf)
                            sessions = s.get("sessions", [])
                            total_bytes = s.get("original_total_bytes", 0) or s.get(
                                "cumulative_transferred_bytes", 0
                            )
                            total_files = s.get("original_total_files", 0) or s.get(
                                "cumulative_files_done", 0
                            )
                            last_session = sessions[-1] if sessions else {}
                            history.append(
                                {
                                    "id": f.replace("cloudhop_", "").replace("_state.json", ""),
                                    "label": s.get("transfer_label", TRANSFER_LABEL),
                                    "sessions": len(sessions),
                                    "cmd": s.get("rclone_cmd", []),
                                    "total_size": fmt_bytes(total_bytes),
                                    "total_files": total_files,
                                    "last_run": last_session.get(
                                        "end", last_session.get("start", "")
                                    ),
                                }
                            )
                    except Exception:
                        pass
            self._send_json(history)
        elif path == "/favicon.ico":
            self._serve_static("favicon.svg")
        elif path.startswith("/static/"):
            self._serve_static(path[8:])  # strip '/static/'
        elif path == "/dashboard":
            html = render("dashboard.html", PORT=port)
            self._send_html(html)
        elif path == "/wizard":
            html = render("wizard.html", PORT=port)
            self._send_html(html)
        elif path == "/api/presets":
            self._send_json({"presets": list_presets()})
        elif path.startswith("/api/presets/"):
            preset_id = path[len("/api/presets/") :]
            if not re.match(r"^[0-9a-f]{16}$", preset_id):
                self._send_json({"ok": False, "msg": "Invalid preset ID"}, 400)
                return
            preset = get_preset(preset_id)
            if preset is None:
                self._send_json({"ok": False, "msg": "Preset not found"}, 404)
            else:
                self._send_json(preset)
        elif path == "/api/settings":
            self._send_json(load_settings())
        elif path == "/settings":
            html = render("settings.html", PORT=port)
            self._send_html(html)
        elif path == "/":
            if self.manager.is_rclone_running() or self.manager.transfer_active:
                html = render("dashboard.html", PORT=port)
                self._send_html(html)
            else:
                html = render("wizard.html", PORT=port)
                self._send_html(html)
        else:
            self._send_404()

    # ── POST routes ──────────────────────────────────────────────────────

    def do_POST(self) -> None:
        if not self._check_host():
            return
        if self.manager is None:
            self._send_json({"ok": False, "msg": "Server not ready"}, 503)
            return
        if not self._check_csrf():
            return

        # Strip query string for route matching
        path = self.path.split("?")[0]

        if path == "/api/pause":
            self._send_json(self.manager.pause())
        elif path == "/api/resume":
            self._send_json(self.manager.resume())
        elif path == "/api/verify":
            self._send_json(self.manager.verify_transfer())
        elif path == "/api/wizard/check-rclone":
            path = find_rclone()
            if path:
                self._send_json({"ok": True, "path": path})
            else:
                self._send_json(
                    {
                        "ok": False,
                        "msg": "rclone not found. Please install from https://rclone.org/install/",
                    }
                )
        elif path == "/api/wizard/install-rclone":
            # Check if already installed
            path = find_rclone()
            if path:
                logger.info("rclone already installed at %s", path)
                self._send_json({"ok": True, "path": path})
                return
            import hashlib
            import platform as _platform
            import shutil
            import tempfile
            import zipfile

            system = _platform.system().lower()
            logger.info("Attempting to install rclone on %s", system)

            if system == "windows":
                logger.error("Automatic rclone installation not supported on Windows")
                self._send_json(
                    {
                        "ok": False,
                        "msg": "Please install rclone manually from https://rclone.org/downloads/",
                    }
                )
                return

            try:
                if system == "darwin" and shutil.which("brew"):
                    logger.info("Installing rclone via Homebrew")
                    result = subprocess.run(
                        ["brew", "install", "rclone"],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if result.returncode == 0:
                        path = find_rclone()
                        if path:
                            logger.info("rclone installed via Homebrew at %s", path)
                            self._send_json({"ok": True, "path": path})
                            return
                    logger.warning(
                        "Homebrew install failed (rc=%d), trying direct download",
                        result.returncode,
                    )

                # Download rclone binary directly (no script execution)
                machine = _platform.machine().lower()
                if machine in ("x86_64", "amd64"):
                    arch = "amd64"
                elif machine in ("aarch64", "arm64"):
                    arch = "arm64"
                else:
                    arch = machine

                os_name = "linux" if system == "linux" else "osx"
                zip_name = f"rclone-current-{os_name}-{arch}.zip"
                download_url = f"https://downloads.rclone.org/{zip_name}"
                checksum_url = f"{download_url}.sha256sum"

                dl_dir = tempfile.mkdtemp(prefix="rclone_install_")
                try:
                    zip_path = os.path.join(dl_dir, zip_name)
                    checksum_path = os.path.join(dl_dir, "sha256sum")

                    logger.info("Downloading rclone binary from %s", download_url)
                    dl_result = subprocess.run(
                        ["curl", "-fsSL", "-o", zip_path, download_url],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if dl_result.returncode != 0:
                        logger.error("Failed to download rclone binary: %s", dl_result.stderr)
                        self._send_json(
                            {
                                "ok": False,
                                "msg": "Failed to download rclone. Please install manually from https://rclone.org/install/",
                            }
                        )
                        return

                    logger.info("Downloading SHA256 checksum from %s", checksum_url)
                    cs_result = subprocess.run(
                        ["curl", "-fsSL", "-o", checksum_path, checksum_url],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if cs_result.returncode != 0:
                        logger.error("Failed to download checksum file: %s", cs_result.stderr)
                        self._send_json(
                            {
                                "ok": False,
                                "msg": "Failed to verify download. Please install manually from https://rclone.org/install/",
                            }
                        )
                        return

                    with open(checksum_path) as cf:
                        expected_hash = cf.read().strip().split()[0].lower()

                    sha256 = hashlib.sha256()
                    with open(zip_path, "rb") as zf:
                        for chunk in iter(lambda: zf.read(8192), b""):
                            sha256.update(chunk)
                    actual_hash = sha256.hexdigest().lower()

                    if actual_hash != expected_hash:
                        logger.error(
                            "SHA256 checksum mismatch: expected %s, got %s",
                            expected_hash,
                            actual_hash,
                        )
                        self._send_json(
                            {
                                "ok": False,
                                "msg": "Checksum verification failed. Please install manually from https://rclone.org/install/",
                            }
                        )
                        return
                    logger.info("SHA256 checksum verified successfully")

                    with zipfile.ZipFile(zip_path) as archive:
                        rclone_entry = None
                        for name in archive.namelist():
                            if name.endswith("/rclone"):
                                rclone_entry = name
                                break
                        if not rclone_entry:
                            raise RuntimeError("rclone binary not found in archive")
                        logger.info("Extracting %s", rclone_entry)
                        archive.extract(rclone_entry, dl_dir)
                        extracted_binary = os.path.join(dl_dir, rclone_entry)

                    install_dir = os.path.expanduser("~/.local/bin")
                    os.makedirs(install_dir, exist_ok=True)
                    dest = os.path.join(install_dir, "rclone")
                    shutil.copy2(extracted_binary, dest)
                    os.chmod(dest, 0o755)
                    logger.info("rclone binary installed to %s", dest)

                    path = find_rclone()
                    if not path:
                        path = dest
                    logger.info("rclone installed successfully at %s", path)
                    self._send_json({"ok": True, "path": path})
                    return
                finally:
                    shutil.rmtree(dl_dir, ignore_errors=True)
            except subprocess.TimeoutExpired:
                logger.error("rclone installation timed out after 120 seconds")
                self._send_json(
                    {
                        "ok": False,
                        "msg": "Installation timed out. Please install manually from https://rclone.org/install/",
                    }
                )
            except Exception as e:
                logger.error("rclone installation error: %s", e)
                self._send_json(
                    {
                        "ok": False,
                        "msg": "Installation failed. Please install manually from https://rclone.org/install/",
                    }
                )
        elif path == "/api/wizard/configure-remote":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            name = body.get("name", "")
            rtype = body.get("type", "")
            username = body.get("username", None)
            password = body.get("password", None)
            if not name or not rtype:
                self._send_json({"ok": False, "msg": "Missing name or type"})
            elif not validate_rclone_input(name, "name") or not validate_rclone_input(
                rtype, "type"
            ):
                self._send_json({"ok": False, "msg": "Invalid input"})
            else:
                twofa = body.get("twofa", "")
                if twofa and (len(twofa) != 6 or not twofa.isdigit()):
                    self._send_json({"ok": False, "msg": "Invalid 2FA code"}, 400)
                    return
                if not _configure_lock.acquire(blocking=False):
                    logger.info("configure-remote: lock already held, returning 409")
                    self._send_json(
                        {"ok": False, "msg": "Configuration in progress, please wait"},
                        409,
                    )
                    return
                try:
                    logger.info("configure-remote: acquired lock for remote '%s'", name)
                    result = self.manager.configure_remote(
                        name,
                        rtype,
                        username=username,
                        password=password,
                        twofa=twofa or None,
                    )
                finally:
                    _configure_lock.release()
                    logger.info("configure-remote: released lock for remote '%s'", name)
                self._send_json(result)
        elif path == "/api/wizard/check-remote":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            name = body.get("name", "")
            if not validate_rclone_input(name, "name"):
                self._send_json({"ok": False, "msg": "Invalid remote name"}, 400)
                return
            self._send_json({"configured": remote_exists(name)})
        elif path == "/api/wizard/validate-path":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            path = body.get("path", "")
            # F313: URL-decode path to handle diacritics (ă, î, ș, ț, â)
            path = urllib.parse.unquote(path)
            if not path:
                self._send_json({"exists": False, "is_directory": False})
                return
            if not validate_rclone_input(path, "path"):
                self._send_json({"ok": False, "msg": "Invalid path"}, 400)
                return
            # Restrict local paths to home directory
            home = os.path.expanduser("~")
            real_path = os.path.realpath(os.path.expandvars(path))
            if not real_path.startswith(home + os.sep) and real_path != home:
                logger.info("[F313] Path validation: path=%s, result=outside_home", path)
                self._send_json(
                    {"ok": False, "msg": "Path outside allowed directory"},
                    403,
                )
                return
            exists = os.path.exists(real_path)
            is_dir = os.path.isdir(real_path) if exists else False
            if not exists:
                logger.info("[F313] Path validation: path=%s, result=not_found", path)
                self._send_json(
                    {
                        "ok": False,
                        "msg": "Path does not exist",
                        "exists": False,
                        "is_directory": False,
                    },
                    404,
                )
                return
            logger.info("[F313] Path validation: path=%s, result=ok", path)
            self._send_json({"exists": exists, "is_directory": is_dir})
        elif path == "/api/wizard/browse":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            source = body.get("path", "")
            if not source:
                source = os.path.expanduser("~")
            if not validate_rclone_input(source, "path"):
                self._send_json({"ok": False, "msg": "Invalid path"}, 400)
                return
            # Restrict local paths (no ":" means not a remote) to home directory
            if ":" not in source:
                home = os.path.expanduser("~")
                real_path = os.path.realpath(os.path.expandvars(source))
                if not real_path.startswith(home + os.sep) and real_path != home:
                    logger.info("Browse blocked: path %s is outside home directory", source)
                    self._send_json(
                        {"ok": False, "msg": "Browsing is restricted to home directory"},
                        403,
                    )
                    return
            try:
                result = subprocess.run(
                    ["rclone", "lsjson", source, "--dirs-only", "--no-modtime"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    items = json.loads(result.stdout)
                    folders = sorted(
                        [
                            {"name": item["Name"], "path": item.get("Path", item["Name"])}
                            for item in items
                        ],
                        key=lambda x: x["name"].lower(),
                    )
                    self._send_json({"ok": True, "folders": folders[:200]})
                else:
                    self._send_json({"ok": False, "msg": "Could not list folders"})
            except subprocess.TimeoutExpired:
                self._send_json({"ok": False, "msg": "Folder listing timed out"})
            except Exception:
                logger.exception("[S507] Browse failed")
                self._send_json({"ok": False, "msg": "Failed to list folders"})
        elif path == "/api/wizard/preview":
            body = self._read_body()
            if body is not None:
                source = body.get("source", "")
                logger.debug("Preview source path: %s", source)
                if not validate_rclone_input(source, "source"):
                    self._send_json({"ok": False, "msg": "Invalid source"}, 400)
                    return
                try:
                    size_cmd = [
                        "rclone",
                        "size",
                        source,
                        "--json",
                    ]
                    for excl in SYSTEM_EXCLUDES:
                        size_cmd.append(f"--exclude={excl}")
                    result = subprocess.run(
                        size_cmd,
                        capture_output=True,
                        text=True,
                        timeout=RCLONE_PREVIEW_TIMEOUT_SEC,
                    )
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        size_bytes = data.get("bytes", 0)
                        if size_bytes > 1073741824:
                            size_str = f"{size_bytes / 1073741824:.2f} GiB"
                        elif size_bytes > 1048576:
                            size_str = f"{size_bytes / 1048576:.1f} MiB"
                        else:
                            size_str = f"{size_bytes / 1024:.0f} KiB"

                        # Estimate transfer duration based on provider speeds
                        source_type = body.get("source_type", "")
                        dest_type = body.get("dest_type", "")
                        bw_limit_str = body.get("bw_limit", "")
                        est_dur, est_sec, speed_est = _estimate_duration(
                            size_bytes, source_type, dest_type, bw_limit_str
                        )

                        file_count = data.get("count", 0)
                        speed_label = f"{speed_est / (1024 * 1024):.0f} MB/s"
                        logger.info(
                            "Preview ETA estimate: %s for %s at %s",
                            est_dur,
                            size_str,
                            speed_label,
                        )
                        self._send_json(
                            {
                                "ok": True,
                                "count": file_count,
                                "size": size_str,
                                "size_bytes": size_bytes,
                                "estimated_duration": est_dur,
                                "estimated_duration_sec": int(est_sec),
                                "estimated_disclaimer": "Estimate based on typical speeds. Actual time may vary.",
                            }
                        )
                    else:
                        self._send_json({"ok": False, "msg": "Could not scan source"})
                except subprocess.TimeoutExpired:
                    self._send_json({"ok": False, "msg": "Scan timed out (source too large)"})
                except Exception as e:
                    self._send_json({"ok": False, "msg": str(e)})
            else:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
        elif path == "/api/wizard/preview-multi":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            paths = body.get("paths", [])
            if not isinstance(paths, list) or not paths:
                self._send_json({"ok": False, "msg": "No paths provided"}, 400)
                return
            if len(paths) > 50:
                self._send_json({"ok": False, "msg": "Too many paths (max 50)"}, 400)
                return
            source_type = body.get("source_type", "")
            dest_type = body.get("dest_type", "")
            bw_limit_str = body.get("bw_limit", "")
            total_files = 0
            total_bytes = 0
            sources_info = []
            for p in paths:
                if not isinstance(p, str) or not p:
                    continue
                if not validate_rclone_input(p, "source"):
                    self._send_json({"ok": False, "msg": f"Invalid path: {p}"}, 400)
                    return
                try:
                    size_cmd = ["rclone", "size", p, "--json"]
                    for excl in SYSTEM_EXCLUDES:
                        size_cmd.append(f"--exclude={excl}")
                    result = subprocess.run(
                        size_cmd,
                        capture_output=True,
                        text=True,
                        timeout=RCLONE_PREVIEW_TIMEOUT_SEC,
                    )
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        fc = data.get("count", 0)
                        sb = data.get("bytes", 0)
                        total_files += fc
                        total_bytes += sb
                        sources_info.append({"path": p, "files": fc, "bytes": sb})
                    else:
                        sources_info.append(
                            {"path": p, "files": 0, "bytes": 0, "error": "scan failed"}
                        )
                except subprocess.TimeoutExpired:
                    sources_info.append({"path": p, "files": 0, "bytes": 0, "error": "timeout"})
                except Exception as e:
                    sources_info.append({"path": p, "files": 0, "bytes": 0, "error": str(e)})
            # Format combined size
            if total_bytes > 1073741824:
                size_str = f"{total_bytes / 1073741824:.2f} GiB"
            elif total_bytes > 1048576:
                size_str = f"{total_bytes / 1048576:.1f} MiB"
            else:
                size_str = f"{total_bytes / 1024:.0f} KiB"
            # ETA estimate
            est_dur, est_sec, speed_est = _estimate_duration(
                total_bytes, source_type, dest_type, bw_limit_str
            )
            logger.info(
                "Multi-select: %d items selected, total %d files, %s",
                len(paths),
                total_files,
                size_str,
            )
            self._send_json(
                {
                    "ok": True,
                    "count": total_files,
                    "size": size_str,
                    "size_bytes": total_bytes,
                    "sources": sources_info,
                    "num_sources": len(paths),
                    "estimated_duration": est_dur,
                    "estimated_duration_sec": int(est_sec),
                    "estimated_disclaimer": "Estimate based on typical speeds. Actual time may vary.",
                }
            )
        elif path == "/api/schedule":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return

            start_time = body.get("start_time", "22:00")
            end_time = body.get("end_time", "06:00")
            time_re = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
            if not time_re.match(start_time) or not time_re.match(end_time):
                self._send_json({"ok": False, "msg": "Invalid time format (use HH:MM)"}, 400)
                return
            days = body.get("days", [0, 1, 2, 3, 4, 5, 6])
            if not isinstance(days, list) or not all(
                isinstance(d, int) and 0 <= d <= 6 for d in days
            ):
                self._send_json({"ok": False, "msg": "Invalid days"}, 400)
                return
            bw_in = body.get("bw_limit_in_window", "")
            bw_out = body.get("bw_limit_out_window", "0")
            with self.manager.state_lock:
                self.manager.state["schedule"] = {
                    "enabled": bool(body.get("enabled", False)),
                    "start_time": start_time,
                    "end_time": end_time,
                    "days": days,
                    "bw_limit_in_window": bw_in,
                    "bw_limit_out_window": bw_out,
                }
                self.manager.save_state()
            self._send_json({"ok": True})
        elif path == "/api/wizard/start":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            # F310: Validate remote name before starting transfer
            dest = body.get("dest", "")
            dest_type = body.get("dest_type", "")
            source = body.get("source", "")
            source_type = body.get("source_type", "")
            # F707: Reject transfer when source equals destination
            if source and dest and source.rstrip("/").lower() == dest.rstrip("/").lower():
                logger.warning("[F707] Rejected transfer: source equals destination: %s", source)
                self._send_json(
                    {"ok": False, "msg": "Source and destination cannot be the same"},
                    400,
                )
                return
            for _label, rtype, rpath in [
                ("destination", dest_type, dest),
                ("source", source_type, source),
            ]:
                if rtype and rtype != "local" and rtype != "icloud" and ":" in rpath:
                    remote_name = rpath.split(":")[0]
                    if not remote_exists(remote_name):
                        logger.warning(
                            "[F310] Remote validation failed: %s not in configured remotes",
                            remote_name,
                        )
                        self._send_json(
                            {
                                "ok": False,
                                "msg": (
                                    f"Remote '{remote_name}' not found. "
                                    "Configure it with 'rclone config'."
                                ),
                            },
                            400,
                        )
                        return
            logger.info(
                "Starting transfer: %s -> %s", body.get("source", "?"), body.get("dest", "?")
            )
            result = self.manager.start_transfer(body)
            if result.get("ok"):
                logger.info("Transfer started (PID %s)", result.get("pid"))
            else:
                logger.error("Transfer failed to start: %s", result.get("msg"))
            self._send_json(result)
        elif path == "/api/wizard/start-multi":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            paths = body.get("paths", [])
            dest = body.get("dest", "")
            if not isinstance(paths, list) or not paths:
                self._send_json({"ok": False, "msg": "No paths provided"}, 400)
                return
            if not dest:
                self._send_json({"ok": False, "msg": "Missing destination"}, 400)
                return
            # F707: Reject if any source path equals destination
            dest_norm = dest.rstrip("/").lower()
            for p in paths:
                if isinstance(p, str) and p.rstrip("/").lower() == dest_norm:
                    logger.warning("[F707] Rejected transfer: source equals destination: %s", p)
                    self._send_json(
                        {"ok": False, "msg": "Source and destination cannot be the same"},
                        400,
                    )
                    return
            transfers = body.get("transfers", "8")
            excludes = body.get("excludes", [])
            source_type = body.get("source_type", "")
            dest_type = body.get("dest_type", "")
            bw_limit = body.get("bw_limit", "")
            checksum = body.get("checksum", False)
            fast_list = body.get("fast_list", False)
            mode = body.get("mode", "copy")
            dry_run = body.get("dry_run", False)
            # First path starts immediately, rest go to queue
            first_body = {
                "source": paths[0],
                "dest": dest,
                "transfers": transfers,
                "excludes": excludes,
                "source_type": source_type,
                "dest_type": dest_type,
                "bw_limit": bw_limit,
                "checksum": checksum,
                "fast_list": fast_list,
                "mode": mode,
                "dry_run": dry_run,
            }
            logger.info(
                "Multi-select start: %d paths, first=%s -> %s",
                len(paths),
                paths[0],
                dest,
            )
            result = self.manager.start_transfer(first_body)
            queue_ids = []
            # Queue remaining paths
            for p in paths[1:]:
                q_body = {
                    "source": p,
                    "dest": dest,
                    "source_type": source_type,
                    "dest_type": dest_type,
                    "transfers": transfers,
                    "excludes": excludes,
                    "bw_limit": bw_limit,
                    "mode": mode,
                    "dry_run": dry_run,
                }
                qr = self.manager.queue_add(q_body)
                if qr.get("ok"):
                    queue_ids.append(qr["queue_id"])
            if result.get("ok"):
                logger.info(
                    "Multi-select: first transfer started (PID %s), %d queued",
                    result.get("pid"),
                    len(queue_ids),
                )
            else:
                logger.error("Multi-select: first transfer failed: %s", result.get("msg"))
            result["queued"] = queue_ids
            result["total_paths"] = len(paths)
            self._send_json(result)
        elif path == "/api/wizard/start-multi-dest":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            source = body.get("source", "")
            destinations = body.get("destinations", [])
            if not source:
                self._send_json({"ok": False, "msg": "Missing source"}, 400)
                return
            if not isinstance(destinations, list) or not destinations:
                self._send_json({"ok": False, "msg": "No destinations provided"}, 400)
                return
            if len(destinations) > 5:
                self._send_json({"ok": False, "msg": "Too many destinations (max 5)"}, 400)
                return
            # F707: Reject if any destination equals source
            source_norm = source.rstrip("/").lower()
            for d in destinations:
                d_path = d.get("path", "") if isinstance(d, dict) else str(d)
                if d_path.rstrip("/").lower() == source_norm:
                    logger.warning(
                        "[F707] Rejected transfer: source equals destination: %s",
                        source,
                    )
                    self._send_json(
                        {"ok": False, "msg": "Source and destination cannot be the same"},
                        400,
                    )
                    return
            transfers = body.get("transfers", "8")
            excludes = body.get("excludes", [])
            source_type = body.get("source_type", "")
            bw_limit = body.get("bw_limit", "")
            checksum = body.get("checksum", False)
            fast_list = body.get("fast_list", False)
            mode = body.get("mode", "copy")
            dry_run = body.get("dry_run", False)
            # First destination starts immediately, rest go to queue
            first_dest = destinations[0]
            first_body = {
                "source": source,
                "dest": first_dest.get("path", ""),
                "transfers": transfers,
                "excludes": excludes,
                "source_type": source_type,
                "dest_type": first_dest.get("remote", ""),
                "bw_limit": bw_limit,
                "checksum": checksum,
                "fast_list": fast_list,
                "mode": mode,
                "dry_run": dry_run,
            }
            logger.info(
                "Multi-dest: %d destinations for source %s",
                len(destinations),
                source,
            )
            result = self.manager.start_transfer(first_body)
            queue_ids = []
            for d in destinations[1:]:
                q_body = {
                    "source": source,
                    "dest": d.get("path", ""),
                    "source_type": source_type,
                    "dest_type": d.get("remote", ""),
                    "transfers": transfers,
                    "excludes": excludes,
                    "bw_limit": bw_limit,
                    "mode": mode,
                    "dry_run": dry_run,
                }
                qr = self.manager.queue_add(q_body)
                if qr.get("ok"):
                    queue_ids.append(qr["queue_id"])
            if result.get("ok"):
                logger.info(
                    "Multi-dest: first transfer started (PID %s), %d queued",
                    result.get("pid"),
                    len(queue_ids),
                )
            else:
                logger.error("Multi-dest: first transfer failed: %s", result.get("msg"))
            result["queued"] = queue_ids
            result["total_destinations"] = len(destinations)
            self._send_json(result)
        elif path == "/api/bwlimit":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            limit = body.get("rate", "")
            if not limit:
                self._send_json({"ok": False, "msg": "Missing rate"}, 400)
                return
            if not validate_rclone_input(limit, "rate"):
                self._send_json({"ok": False, "msg": "Invalid rate"}, 400)
                return
            result = self.manager.set_bandwidth(limit)
            self._send_json(result)
        elif path == "/api/queue/add":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            logger.info("Queue API: add transfer")
            self._send_json(self.manager.queue_add(body))
        elif path == "/api/queue/start-next":
            logger.info("Queue API: start next")
            self._send_json(self.manager.queue_process_next())
        elif path == "/api/presets":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            name = body.get("name", "")
            config = body.get("config", {})
            if not name or not isinstance(config, dict):
                self._send_json({"ok": False, "msg": "Missing name or config"}, 400)
                return
            preset_id = save_preset(name, config)
            self._send_json({"ok": True, "preset_id": preset_id})
        elif re.match(r"^/api/presets/[0-9a-f]{16}/run$", self.path):
            preset_id = self.path.split("/")[3]
            result = run_preset(preset_id, self.manager)
            self._send_json(result)
        elif path == "/api/history/resume":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            transfer_id = body.get("id", "")
            if not transfer_id or not re.match(r"^[0-9a-f]{16}$", transfer_id):
                logger.info("Invalid transfer ID format rejected: %r", transfer_id)
                self._send_json({"ok": False, "msg": "Invalid transfer ID"}, 400)
                return
            state_file = os.path.join(_CM_DIR, f"cloudhop_{transfer_id}_state.json")
            # Prevent directory traversal
            if not os.path.realpath(state_file).startswith(os.path.realpath(_CM_DIR) + os.sep):
                self._send_json({"ok": False, "msg": "Invalid transfer ID"}, 400)
                return
            if not os.path.exists(state_file):
                self._send_json({"ok": False, "msg": "Transfer not found"}, 404)
                return
            try:
                with open(state_file) as sf:
                    saved = json.load(sf)
                cmd = saved.get("rclone_cmd", [])
                if not cmd:
                    self._send_json({"ok": False, "msg": "No command saved for this transfer"})
                    return
                if not validate_rclone_cmd(cmd):
                    logger.error("History resume refused: command failed validation: %s", cmd)
                    self._send_json(
                        {"ok": False, "msg": "Saved command failed security validation"}, 400
                    )
                    return
                # Switch manager to this transfer (under lock)
                log_file = os.path.join(_CM_DIR, f"cloudhop_{transfer_id}.log")
                with self.manager.state_lock:
                    self.manager.state_file = state_file
                    self.manager.log_file = log_file
                    self.manager.rclone_cmd = cmd
                    self.manager.transfer_label = saved.get("transfer_label", TRANSFER_LABEL)
                    self.manager.state = saved
                result = self.manager.resume()
                self._send_json(result)
            except Exception as e:
                logger.error("History resume error: %s", e)
                self._send_json({"ok": False, "msg": "Failed to resume transfer"})
        elif path == "/api/settings":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            result = save_settings(body)
            self._send_json(result, 200 if result.get("ok") else 400)
        elif path == "/api/settings/test-email":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            from .email_notify import send_email
            from .settings import load_settings_with_secrets

            settings = load_settings_with_secrets()
            for key in (
                "email_smtp_host",
                "email_smtp_port",
                "email_smtp_tls",
                "email_from",
                "email_to",
                "email_username",
                "email_password",
            ):
                if key in body and body[key] != "":
                    settings[key] = body[key]
            try:
                settings["email_smtp_port"] = int(settings.get("email_smtp_port", 587))
            except (ValueError, TypeError):
                settings["email_smtp_port"] = 587
            try:
                ok = send_email(
                    "CloudHop Test Email",
                    "<div style='font-family:-apple-system,sans-serif;max-width:500px;"
                    "margin:0 auto;padding:32px;'>"
                    "<h2 style='color:#22c55e;'>CloudHop Email Test</h2>"
                    "<p>If you received this, email notifications are working.</p>"
                    "<p style='color:#888;font-size:13px;margin-top:24px;'>Sent by CloudHop</p>"
                    "</div>",
                    settings,
                )
                if ok:
                    self._send_json({"ok": True, "msg": "Test email sent successfully"})
                else:
                    self._send_json({"ok": False, "msg": "Failed to send. Check SMTP settings."})
            except Exception as e:
                logger.error("Test email error: %s", e)
                self._send_json({"ok": False, "msg": "Email error. Check SMTP settings."})
        else:
            self._send_404()

    # ── DELETE routes ────────────────────────────────────────────────────

    def do_DELETE(self) -> None:
        if not self._check_host():
            return
        if self.manager is None:
            self._send_json({"ok": False, "msg": "Server not ready"}, 503)
            return
        if not self._check_csrf():
            return

        # Strip query string for route matching
        path = self.path.split("?")[0]

        # DELETE /api/presets/<preset_id>
        m = re.match(r"^/api/presets/([0-9a-f]{16})$", path)
        if m:
            preset_id = m.group(1)
            if delete_preset(preset_id):
                self._send_json({"ok": True})
            else:
                self._send_json({"ok": False, "msg": "Preset not found"}, 404)
            return

        # DELETE /api/queue/<queue_id>
        m = re.match(r"^/api/queue/([0-9a-f]{16})$", path)
        if m:
            queue_id = m.group(1)
            logger.info("Queue API: remove %s", queue_id)
            if self.manager.queue_remove(queue_id):
                self._send_json({"ok": True})
            else:
                self._send_json({"ok": False, "msg": "Queue item not found or is active"}, 400)
        else:
            self._send_404()

    # ── PUT routes ────────────────────────────────────────────────────────

    def do_PUT(self) -> None:
        if not self._check_host():
            return
        if self.manager is None:
            self._send_json({"ok": False, "msg": "Server not ready"}, 503)
            return
        if not self._check_csrf():
            return

        # Strip query string for route matching
        path = self.path.split("?")[0]

        # PUT /api/queue/<queue_id>/reorder
        m = re.match(r"^/api/queue/([0-9a-f]{16})/reorder$", path)
        if m:
            queue_id = m.group(1)
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            try:
                position = int(body.get("position", -1))
            except (ValueError, TypeError):
                position = -1
            logger.info("Queue API: reorder %s to position %d", queue_id, position)
            if self.manager.queue_reorder(queue_id, position):
                self._send_json({"ok": True})
            else:
                self._send_json({"ok": False, "msg": "Invalid queue_id or position"}, 400)
        else:
            self._send_404()

    # ── OPTIONS (CORS preflight) ─────────────────────────────────────────

    def do_OPTIONS(self) -> None:
        if not self._check_host():
            return
        self.send_response(204)
        port = self.actual_port
        origin = self.headers.get("Origin", "")
        allowed_origins = {f"http://localhost:{port}", f"http://127.0.0.1:{port}"}
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP access logging."""
        pass

    def handle_one_request(self) -> None:
        """Override to catch errors from disconnected clients and prevent
        BaseException (SystemExit, KeyboardInterrupt) from killing worker
        threads in ThreadingHTTPServer, which causes ERR_CONNECTION_REFUSED."""
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            logger.debug("Client disconnected mid-request")
        except Exception as e:
            logger.exception("[F602] Unhandled error in request handler: %s", e)
        except BaseException as e:
            # F602: SystemExit/KeyboardInterrupt must not propagate in worker
            # threads or the ThreadingHTTPServer loses its ability to accept
            # new connections, causing ERR_CONNECTION_REFUSED.
            logger.error(
                "[F602] BaseException caught in request handler (prevented crash): %s: %s",
                type(e).__name__,
                e,
            )
