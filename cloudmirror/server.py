"""CloudMirror HTTP server."""
import http.server
import json
import hmac
import secrets
import os
import platform
import shutil
import subprocess

from .transfer import TransferManager
from .templates import render
from .utils import (
    PORT,
    MAX_REQUEST_BODY_BYTES,
    RCLONE_INSTALL_TIMEOUT_SEC,
    RCLONE_PREVIEW_TIMEOUT_SEC,
    validate_rclone_input,
    validate_exclude_pattern,
    find_rclone,
    get_existing_remotes,
    remote_exists,
    configure_remote_api,
    _CM_DIR,
    TRANSFER_LABEL,
)

CSRF_TOKEN = secrets.token_hex(32)


class CloudMirrorHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for CloudMirror."""

    # Class-level reference to the TransferManager instance.
    # Must be set before starting the server.
    manager: TransferManager = None

    # ── Response helpers ────────────────────────────────────────────────

    def _send_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        # Only allow CORS from localhost to prevent cross-site request forgery
        # from malicious pages that might try to start transfers.
        origin = self.headers.get("Origin", "")
        port = PORT
        allowed_origins = {f"http://localhost:{port}", f"http://127.0.0.1:{port}"}
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self, html: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"csrf_token={CSRF_TOKEN}; Path=/; SameSite=Strict")
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_static(self, filename: str):
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
        content_types = {"css": "text/css", "js": "application/javascript"}
        self.send_response(200)
        self.send_header("Content-Type", content_types.get(ext, "text/plain"))
        self.end_headers()
        with open(filepath, "rb") as f:
            self.wfile.write(f.read())

    # ── Security checks ─────────────────────────────────────────────────

    def _check_csrf(self):
        """Verify CSRF token from X-CSRF-Token header matches the server token."""
        token = self.headers.get("X-CSRF-Token")
        if not hmac.compare_digest(token or "", CSRF_TOKEN):
            self._send_json({"ok": False, "msg": "CSRF token invalid"}, 403)
            return False
        return True

    def _check_host(self):
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

    def _read_body(self):
        """Read and parse the JSON request body with a size cap."""
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_REQUEST_BODY_BYTES:
            return None
        if length > 0:
            try:
                return json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError):
                return None
        return {}

    # ── GET routes ───────────────────────────────────────────────────────

    def do_GET(self):
        if not self._check_host():
            return

        port = PORT

        if self.path == "/api/status":
            self._send_json(self.manager.parse_current())
        elif self.path == "/api/wizard/status":
            self._send_json({
                "rclone_installed": find_rclone() is not None,
                "remotes": get_existing_remotes(),
                "home_dir": os.path.expanduser("~"),
            })
        elif self.path == "/api/history":
            history = []
            for f in sorted(os.listdir(_CM_DIR)):
                if f.endswith("_state.json"):
                    try:
                        with open(os.path.join(_CM_DIR, f)) as sf:
                            s = json.load(sf)
                            history.append({
                                "id": f.replace("cloudmirror_", "").replace("_state.json", ""),
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

    def do_POST(self):
        if not self._check_host():
            return
        if not self._check_csrf():
            return

        if self.path == "/api/pause":
            self._send_json(self.manager.pause_rclone())
        elif self.path == "/api/resume":
            self._send_json(self.manager.resume_rclone())
        elif self.path == "/api/wizard/check-rclone":
            path = find_rclone()
            if path:
                self._send_json({"ok": True, "path": path})
            else:
                # Try to install
                try:
                    system = platform.system().lower()
                    if system == "darwin" and shutil.which("brew"):
                        subprocess.run(
                            ["brew", "install", "rclone"],
                            capture_output=True,
                            timeout=RCLONE_INSTALL_TIMEOUT_SEC,
                        )
                    elif system in ("darwin", "linux"):
                        subprocess.run(
                            ["bash", "-c", "curl -s https://rclone.org/install.sh | sudo bash"],
                            capture_output=True,
                            timeout=RCLONE_INSTALL_TIMEOUT_SEC,
                        )
                    path = find_rclone()
                    self._send_json({"ok": path is not None, "path": path or ""})
                except Exception as e:
                    self._send_json({"ok": False, "msg": str(e)})
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
                result = configure_remote_api(name, rtype, username=username, password=password)
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
        elif self.path == "/api/wizard/start":
            body = self._read_body()
            if body is None:
                self._send_json({"ok": False, "msg": "Invalid request"}, 400)
                return
            result = self.manager.start_transfer_from_wizard(body)
            self._send_json(result)
        else:
            self.send_response(404)
            self.end_headers()

    # ── OPTIONS (CORS preflight) ─────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(204)
        port = PORT
        origin = self.headers.get("Origin", "")
        allowed_origins = {f"http://localhost:{port}", f"http://127.0.0.1:{port}"}
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress default HTTP access logging."""
        pass
