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
POST /api/wizard/check-rclone Install rclone if missing
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
import hmac
import secrets
import os
import logging
import platform
import shutil
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger("cloudhop.server")

from .transfer import (
    TransferManager,
    find_rclone,
    get_existing_remotes,
    remote_exists,
)
from .templates import render
from .utils import (
    PORT,
    MAX_REQUEST_BODY_BYTES,
    RCLONE_INSTALL_TIMEOUT_SEC,
    RCLONE_PREVIEW_TIMEOUT_SEC,
    validate_rclone_input,
    _CM_DIR,
    TRANSFER_LABEL,
)

CSRF_TOKEN = secrets.token_hex(32)


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
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"csrf_token={CSRF_TOKEN}; Path=/; SameSite=Strict")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_static(self, filename: str) -> None:
        """Serve static CSS/JS files."""
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        # Prevent directory traversal by resolving the real path and ensuring
        # it stays within the static directory.
        filepath = os.path.realpath(os.path.join(static_dir, filename))
        if not filepath.startswith(os.path.realpath(static_dir)):
            self.send_response(403)
            self.end_headers()
            return
        if not os.path.exists(filepath):
            self.send_response(404)
            self.end_headers()
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
        """Verify CSRF token from X-CSRF-Token header matches the server token."""
        token = self.headers.get("X-CSRF-Token")
        if not hmac.compare_digest(token or "", CSRF_TOKEN):
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
        elif self.path == "/api/wizard/status":
            self._send_json({
                "rclone_installed": find_rclone() is not None,
                "remotes": get_existing_remotes(),
                "home_dir": os.path.expanduser("~"),
            })
        elif self.path == "/api/schedule":
            with self.manager.state_lock:
                schedule = dict(self.manager.state.get("schedule", {}))
            if hasattr(self.manager, 'is_in_schedule_window'):
                schedule["in_window"] = self.manager.is_in_schedule_window()
            else:
                schedule["in_window"] = True
            self._send_json(schedule)
        elif self.path == "/api/history":
            history = []
            for f in sorted(os.listdir(_CM_DIR)):
                if f.endswith("_state.json"):
                    try:
                        with open(os.path.join(_CM_DIR, f)) as sf:
                            s = json.load(sf)
                            history.append({
                                "id": f.replace("cloudhop_", "").replace("_state.json", ""),
                                "label": s.get("transfer_label", TRANSFER_LABEL),
                                "sessions": len(s.get("sessions", [])),
                                "cmd": s.get("rclone_cmd", []),
                            })
                    except Exception:
                        pass
            self._send_json(history)
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
            self.send_response(404)
            self.end_headers()

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
        elif self.path == "/api/wizard/check-rclone":
            path = find_rclone()
            if path:
                self._send_json({"ok": True, "path": path})
            else:
                self._send_json({"ok": False, "msg": "rclone not found. Please install from https://rclone.org/install/"})
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
            elif not validate_rclone_input(name, "name") or not validate_rclone_input(rtype, "type"):
                self._send_json({"ok": False, "msg": "Invalid input"})
            else:
                result = self.manager.configure_remote(name, rtype, username=username, password=password)
                self._send_json(result)
        elif self.path == "/api/wizard/check-remote":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            name = body.get("name", "")
            self._send_json({"configured": remote_exists(name)})
        elif self.path == "/api/wizard/preview":
            body = self._read_body()
            if body is not None:
                source = body.get("source", "")
                if not validate_rclone_input(source, "source"):
                    self._send_json({"ok": False, "msg": "Invalid source"}, 400)
                    return
                try:
                    result = subprocess.run(
                        ["rclone", "size", source, "--json"],
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
                        self._send_json({"ok": True, "count": data.get("count", 0), "size": size_str})
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
            import re
            start_time = body.get("start_time", "22:00")
            end_time = body.get("end_time", "06:00")
            time_re = re.compile(r"^\d{2}:\d{2}$")
            if not time_re.match(start_time) or not time_re.match(end_time):
                self._send_json({"ok": False, "msg": "Invalid time format (use HH:MM)"}, 400)
                return
            days = body.get("days", [0, 1, 2, 3, 4, 5, 6])
            if not isinstance(days, list) or not all(isinstance(d, int) and 0 <= d <= 6 for d in days):
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
            logger.info("Starting transfer: %s -> %s", body.get("source", "?"), body.get("dest", "?"))
            result = self.manager.start_transfer(body)
            if result.get("ok"):
                logger.info("Transfer started (PID %s)", result.get("pid"))
            else:
                logger.error("Transfer failed to start: %s", result.get("msg"))
            self._send_json(result)
        else:
            self.send_response(404)
            self.end_headers()

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
