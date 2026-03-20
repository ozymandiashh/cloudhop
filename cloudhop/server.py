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

import hmac
import http.server
import json
import logging
import os
import secrets
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger("cloudhop.server")

from .templates import render
from .transfer import (
    TransferManager,
    find_rclone,
    get_existing_remotes,
    remote_exists,
)
from .utils import (
    _CM_DIR,
    MAX_REQUEST_BODY_BYTES,
    PORT,
    RCLONE_PREVIEW_TIMEOUT_SEC,
    TRANSFER_LABEL,
    validate_rclone_input,
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

    def _send_404(self) -> None:
        """Return a styled 404 HTML page."""
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<!DOCTYPE html><html><head>"
            b'<meta charset="UTF-8">'
            b'<meta name="viewport" content="width=device-width,initial-scale=1.0">'
            b"<title>404 - CloudHop</title>"
            b"<style>"
            b"body{background:#0b0d13;color:#f0f1f3;font-family:-apple-system,sans-serif;"
            b"display:flex;align-items:center;justify-content:center;min-height:100vh;"
            b"margin:0;text-align:center}"
            b".c{max-width:400px}"
            b".t{font-size:4rem;margin-bottom:16px;opacity:.3}"
            b".h{font-size:1.5rem;font-weight:700;margin-bottom:8px}"
            b".p{color:#6b6f7b;margin-bottom:24px}"
            b"a{color:#6366f1;text-decoration:none}"
            b"a:hover{text-decoration:underline}"
            b"</style></head><body>"
            b'<div class="c">'
            b'<div class="t">404</div>'
            b'<div class="h">Page not found</div>'
            b'<p class="p">The page you are looking for does not exist.</p>'
            b'<a href="/">Go to CloudHop</a>'
            b"</div></body></html>"
        )

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
            self._send_json(
                {
                    "rclone_installed": find_rclone() is not None,
                    "remotes": get_existing_remotes(),
                    "home_dir": os.path.expanduser("~"),
                }
            )
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
                result = self.manager.configure_remote(
                    name, rtype, username=username, password=password
                )
                self._send_json(result)
        elif self.path == "/api/wizard/check-remote":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            name = body.get("name", "")
            self._send_json({"configured": remote_exists(name)})
        elif self.path == "/api/wizard/browse":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            source = body.get("path", "")
            if not source or not validate_rclone_input(source, "path"):
                self._send_json({"ok": False, "msg": "Invalid path"}, 400)
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
                        self._send_json(
                            {"ok": True, "count": data.get("count", 0), "size": size_str}
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
            import re

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
        elif self.path == "/api/history/resume":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            transfer_id = body.get("id", "")
            if not transfer_id or not validate_rclone_input(transfer_id, "id"):
                self._send_json({"ok": False, "msg": "Invalid transfer ID"}, 400)
                return
            state_file = os.path.join(_CM_DIR, f"cloudhop_{transfer_id}_state.json")
            # Prevent directory traversal
            if not os.path.realpath(state_file).startswith(os.path.realpath(_CM_DIR)):
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
                # Switch manager to this transfer
                self.manager.state_file = state_file
                log_file = os.path.join(_CM_DIR, f"cloudhop_{transfer_id}.log")
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
