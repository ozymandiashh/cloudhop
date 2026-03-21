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
from typing import Any, Dict, Optional

from . import __version__

logger = logging.getLogger("cloudhop.server")

# Serialises concurrent rclone config create calls (e.g. two browser tabs).
_configure_lock = threading.Lock()

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

        port = self.actual_port

        if self.path == "/api/status":
            self._send_json(self.manager.parse_current())
        elif self.path == "/api/check-update":
            from . import __version__

            try:
                import urllib.request

                req = urllib.request.Request(
                    "https://api.github.com/repos/husamsoboh-cyber/cloudhop/releases/latest",
                    headers={"Accept": "application/vnd.github+json"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())
                tag = data.get("tag_name", "")
                latest = tag.lstrip("v") if tag else __version__
                is_app = getattr(sys, "_MEIPASS", None) is not None
                self._send_json(
                    {
                        "current": __version__,
                        "latest": latest,
                        "update_available": latest != __version__,
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
        elif self.path == "/api/wizard/status":
            self._send_json(
                {
                    "rclone_installed": find_rclone() is not None,
                    "remotes": get_existing_remotes(),
                    "home_dir": os.path.expanduser("~"),
                }
            )
        elif self.path == "/api/error-log":
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
        elif self.path == "/api/queue":
            self._send_json({"queue": self.manager.queue_list()})
        elif self.path == "/api/schedule":
            with self.manager.state_lock:
                schedule = dict(self.manager.state.get("schedule", {}))
            if hasattr(self.manager, "is_in_schedule_window"):
                schedule["in_window"] = self.manager.is_in_schedule_window()
            else:
                schedule["in_window"] = True
            self._send_json(schedule)
        elif self.path == "/api/history":
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
        elif self.path == "/favicon.ico":
            self._serve_static("favicon.svg")
        elif self.path.startswith("/static/"):
            self._serve_static(self.path[8:])  # strip '/static/'
        elif self.path == "/dashboard":
            html = render("dashboard.html", CSRF_TOKEN=CSRF_TOKEN, PORT=port)
            self._send_html(html)
        elif self.path == "/wizard":
            html = render("wizard.html", CSRF_TOKEN=CSRF_TOKEN, PORT=port)
            self._send_html(html)
        elif self.path == "/":
            if self.manager.is_rclone_running() or self.manager.transfer_active:
                html = render("dashboard.html", CSRF_TOKEN=CSRF_TOKEN, PORT=port)
                self._send_html(html)
            else:
                html = render("wizard.html", CSRF_TOKEN=CSRF_TOKEN, PORT=port)
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

        if self.path == "/api/pause":
            self._send_json(self.manager.pause())
        elif self.path == "/api/resume":
            self._send_json(self.manager.resume())
        elif self.path == "/api/verify":
            self._send_json(self.manager.verify_transfer())
        elif self.path == "/api/wizard/check-rclone":
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
        elif self.path == "/api/wizard/install-rclone":
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
        elif self.path == "/api/wizard/configure-remote":
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
        elif self.path == "/api/wizard/check-remote":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            name = body.get("name", "")
            self._send_json({"configured": remote_exists(name)})
        elif self.path == "/api/wizard/validate-path":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            path = body.get("path", "")
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
                logger.info("Validate-path blocked: path %s is outside home directory", path)
                self._send_json(
                    {"ok": False, "msg": "Path validation is restricted to home directory"},
                    403,
                )
                return
            exists = os.path.exists(real_path)
            is_dir = os.path.isdir(real_path) if exists else False
            logger.info("Path validated: %s (exists=%s, is_dir=%s)", path, exists, is_dir)
            self._send_json({"exists": exists, "is_directory": is_dir})
        elif self.path == "/api/wizard/browse":
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
            except Exception as e:
                self._send_json({"ok": False, "msg": str(e)})
        elif self.path == "/api/wizard/preview":
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

                        # B2: Estimate transfer duration
                        source_type = body.get("source_type", "")
                        dest_type = body.get("dest_type", "")
                        bw_limit_str = body.get("bw_limit", "")
                        if bw_limit_str:
                            try:
                                bw_val = float(re.sub(r"[^0-9.]", "", bw_limit_str))
                                speed_est = bw_val * 1024 * 1024
                            except (ValueError, TypeError):
                                speed_est = 10 * 1024 * 1024
                        elif dest_type == "protondrive" or source_type == "protondrive":
                            speed_est = 2 * 1024 * 1024
                        elif source_type == "local" and dest_type == "local":
                            speed_est = 100 * 1024 * 1024
                        elif source_type not in ("local",) and dest_type not in ("local",):
                            speed_est = 5 * 1024 * 1024
                        else:
                            speed_est = 10 * 1024 * 1024
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

                        file_count = data.get("count", 0)
                        logger.info(
                            "Preview scan: %d files, %s total",
                            file_count,
                            size_str,
                        )
                        self._send_json(
                            {
                                "ok": True,
                                "count": file_count,
                                "size": size_str,
                                "size_bytes": size_bytes,
                                "estimated_duration": est_dur,
                                "estimated_duration_sec": int(est_sec),
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
        elif self.path == "/api/schedule":
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
        elif self.path == "/api/wizard/start":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
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
        elif self.path == "/api/bwlimit":
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
        elif self.path == "/api/queue/add":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            self._send_json(self.manager.queue_add(body))
        elif self.path == "/api/queue/remove":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            try:
                idx = int(body.get("index", -1))
            except (ValueError, TypeError):
                idx = -1
            self._send_json(self.manager.queue_remove(idx))
        elif self.path == "/api/history/resume":
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
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP access logging."""
        pass

    def handle_one_request(self) -> None:
        """Override to catch BrokenPipeError from disconnected clients."""
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            logger.debug("Client disconnected mid-request")
        except Exception as e:
            logger.exception("Unhandled error in request handler: %s", e)
