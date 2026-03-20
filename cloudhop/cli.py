"""CloudHop CLI entry point.

Two operating modes
-------------------
Wizard mode (no arguments)
    ``cloudhop``
    Opens the browser-based setup wizard.  rclone is not started by the CLI;
    the wizard POSTs to ``/api/wizard/start`` which launches rclone.

CLI mode (source + destination given)
    ``cloudhop <source> <dest> [--rclone-flags...]``
    Builds and immediately starts the rclone command, then opens the
    dashboard for monitoring.  Any extra ``--flags`` are forwarded verbatim
    to rclone (e.g. ``--bwlimit=10M``, ``--dry-run``).

Attach mode (``--attach-pid=<pid>``)
    ``cloudhop --attach-pid=1234 --attach-log=/path/to/rclone.log``
    Monitors an already-running rclone process that was started externally.
    CloudHop will not try to pause or restart it, but will parse its log
    and display live progress on the dashboard.

Port auto-retry
---------------
``start_dashboard`` tries to bind to port 8787 (``PORT``).  If that port
is busy it retries 8788, 8789, 8790, 8791 before giving up.  The chosen
port is stored in ``CloudHopHandler.actual_port`` so CORS checks use the
correct origin.
"""

import errno
import http.server
import logging
import os
import platform
import signal
import sys
import threading
import webbrowser
from typing import List

from .server import CloudHopHandler
from .transfer import TransferManager, ensure_rclone
from .utils import PORT

logger = logging.getLogger("cloudhop")


def _setup_logging(cm_dir: str) -> None:
    """Configure logging to file + console."""
    log_file = os.path.join(cm_dir, "cloudhop-server.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stderr),
        ],
    )
    logger.info("CloudHop server starting (log: %s)", log_file)


def _cli_subcommand(cmd: str) -> bool:
    """Handle CLI subcommands (status/pause/resume/history). Returns True if handled."""
    import json
    import urllib.request

    port_range = range(8787, 8792)

    def _api(path: str, method: str = "GET") -> dict:
        for port in port_range:
            try:
                url = f"http://127.0.0.1:{port}{path}"
                req = urllib.request.Request(url, method=method)
                req.add_header("Host", f"localhost:{port}")
                if method == "POST":
                    # Get CSRF token from an HTML page (JSON endpoints don't set cookies)
                    resp0 = urllib.request.urlopen(
                        urllib.request.Request(
                            f"http://127.0.0.1:{port}/dashboard",
                            headers={"Host": f"localhost:{port}"},
                        ),
                        timeout=5,
                    )
                    cookies = resp0.headers.get("Set-Cookie", "")
                    token = ""
                    for part in cookies.split(";"):
                        if "csrf_token=" in part:
                            token = part.split("csrf_token=")[1].strip()
                    req.add_header("X-CSRF-Token", token)
                    req.add_header("Content-Type", "application/json")
                    req.data = b"{}"
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return json.loads(resp.read())
            except Exception:
                continue
        return {"error": "CloudHop server not running. Start it with: cloudhop"}

    if cmd == "status":
        d = _api("/api/status")
        if "error" in d and "not running" in d.get("error", ""):
            print("  CloudHop is not running.")
            return True
        pct = d.get("global_pct", 0)
        xfer = d.get("global_transferred", "--")
        total = d.get("global_total", "--")
        speed = d.get("speed", "--")
        eta = d.get("eta", "--")
        running = d.get("rclone_running", False)
        errors = d.get("errors", 0)
        files_done = d.get("global_files_done", 0)
        files_total = d.get("global_files_total", 0)
        print()
        print(f"  CloudHop {'Transferring' if running else 'Stopped'}")
        print(f"  Progress: {pct}% ({xfer} / {total})")
        print(f"  Files:    {files_done} / {files_total}")
        print(f"  Speed:    {speed or '--'}")
        print(f"  ETA:      {eta or '--'}")
        print(f"  Errors:   {errors}")
        print()
        return True

    if cmd == "pause":
        d = _api("/api/pause", method="POST")
        if d.get("ok"):
            print(f"  {d.get('msg', 'Paused')}")
        else:
            print(f"  Error: {d.get('msg', d.get('error', 'Unknown'))}")
        return True

    if cmd == "resume":
        d = _api("/api/resume", method="POST")
        if d.get("ok"):
            print(f"  {d.get('msg', 'Resumed')}")
        else:
            print(f"  Error: {d.get('msg', d.get('error', 'Unknown'))}")
        return True

    if cmd == "history":
        d = _api("/api/history")
        if isinstance(d, list):
            if not d:
                print("  No transfer history.")
            else:
                print()
                for h in d:
                    label = h.get("label", "Unknown")
                    sessions = h.get("sessions", 0)
                    print(f"  {label} ({sessions} sessions)")
                print()
        else:
            print(f"  Error: {d.get('error', 'Unknown')}")
        return True

    return False


def main() -> None:
    """Main entry point -- wizard mode (no args) or CLI mode (source dest [flags])."""
    args = sys.argv[1:]

    # Handle CLI subcommands before initializing the full server
    if len(args) == 1 and args[0] in ("status", "pause", "resume", "history"):
        _cli_subcommand(args[0])
        return

    manager = TransferManager()
    _setup_logging(manager.cm_dir)
    CloudHopHandler.manager = manager

    logger.info("Platform: %s, Python: %s", platform.system(), sys.version.split()[0])
    signal.signal(signal.SIGTERM, lambda signum, frame: _signal_handler(manager))

    # Ignore SIGHUP so CloudHop survives terminal close (Unix only)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

    if len(args) == 0:
        # Web wizard mode
        print()
        print("  +==================================================+")
        print("  |               Welcome to CloudHop                |")
        print("  |                                                   |")
        print("  |   Starting web setup wizard...                    |")
        print("  +==================================================+")
        if platform.system() == "Windows":
            print("  Note: Some features (pause/resume) may not work on Windows.")
            print("  For best results, use macOS or Linux.")
            print()
        start_dashboard(manager, start_rclone=False)
    else:
        # CLI mode for advanced users
        ensure_rclone()
        parse_cli_args(manager, args)
        print()
        if manager.rclone_pid and not manager.rclone_cmd:
            # Attach mode - monitoring existing process
            print(f"  CloudHop - Monitoring PID {manager.rclone_pid}")
            print(f"  Log: {manager.log_file}")
            start_dashboard(manager, start_rclone=False)
        else:
            print("  CloudHop - Advanced Mode")
            print(f"  Command: {' '.join(manager.rclone_cmd)}")
            start_dashboard(manager, start_rclone=True)


def start_dashboard(manager: TransferManager, start_rclone: bool = False) -> None:
    """Start the web dashboard and optionally the rclone process."""
    import subprocess

    # Load RCLONE_CMD from state if not set (enables resume after restart)
    if not manager.rclone_cmd and "rclone_cmd" in manager.state:
        manager.rclone_cmd = manager.state["rclone_cmd"]
        # Restore LOG_FILE from the saved command
        for arg in manager.rclone_cmd:
            if arg.startswith("--log-file="):
                manager.log_file = arg.split("=", 1)[1]
                break

    # Initial full log scan
    print()
    print("  Scanning transfer log...")
    manager.scan_full_log()
    session_count = len(manager.state.get("sessions", []))
    if session_count > 0:
        print(f"  Found {session_count} previous session(s)")

    # Start background scanner
    scanner = threading.Thread(target=manager.background_scanner, daemon=True)
    scanner.start()

    # Start rclone if requested
    if start_rclone and manager.rclone_cmd:
        # Save command and label to state so Resume works after server restart
        with manager.state_lock:
            if "rclone_cmd" not in manager.state:
                manager.state["rclone_cmd"] = manager.rclone_cmd
                manager.state["transfer_label"] = manager.transfer_label
                manager.save_state()
        print("  Starting file transfer...")
        popen_kwargs: dict = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if platform.system().lower() == "windows":
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            DETACHED_PROCESS = 0x00000008
            popen_kwargs["creationflags"] = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(manager.rclone_cmd, **popen_kwargs)
        manager.rclone_pid = proc.pid
        print(f"  Transfer started (PID {proc.pid})")
        manager.transfer_active = True

    port = PORT

    server = None
    for try_port in range(port, port + 5):
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", try_port), CloudHopHandler)
            if try_port != port:
                print(f"  Port {port} was busy, using port {try_port} instead.")
                port = try_port
            CloudHopHandler.actual_port = port
            break
        except OSError as e:
            if (
                "Address already in use" in str(e) or e.errno == errno.EADDRINUSE
            ) and try_port < port + 4:
                continue
            if "Address already in use" in str(e) or e.errno == errno.EADDRINUSE:
                print(f"\n  Error: Ports {port}-{port + 4} are all in use.")
                print("  Please stop the other process(es) and try again.\n")
                sys.exit(1)
            raise

    if server is None:
        print(f"\n  Error: Could not bind to any port in range {port}-{port + 4}.\n")
        sys.exit(1)

    print()
    print(f"  CloudHop: http://localhost:{port}")
    print()
    if manager.transfer_active:
        print("  Open the link above in your browser to monitor progress.")
    else:
        print("  Open the link above in your browser to start the setup wizard.")
    print("  Press Ctrl+C to stop the server.")
    print()

    # Try to open browser automatically (after port binding succeeds)
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

    logger.info("Server listening on http://localhost:%d", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _signal_handler(manager)
    except Exception as e:
        logger.exception("Server crashed: %s", e)
        print(f"\n  CloudHop server crashed: {e}")
        print("  The file transfer continues in the background.")
        print(f"  Check logs: {os.path.join(manager.cm_dir, 'cloudhop-server.log')}")
        print("  Run 'cloudhop' again to reconnect to the dashboard.")
        print()


def parse_cli_args(manager: TransferManager, args: List[str]) -> None:
    """Parse CLI arguments for advanced usage: cloudhop source: dest: [flags]"""
    source = None
    dest = None
    extra_flags = []
    attach_pid = None
    attach_log = None

    for arg in args:
        if arg.startswith("--attach-pid="):
            try:
                attach_pid = int(arg.split("=", 1)[1])
            except ValueError:
                print("  Error: --attach-pid requires a numeric PID")
                sys.exit(1)
        elif arg.startswith("--attach-log="):
            attach_log = arg.split("=", 1)[1]
        elif arg.startswith("--"):
            extra_flags.append(arg)
        elif source is None:
            source = arg
        elif dest is None:
            dest = arg
        else:
            extra_flags.append(arg)

    # Check attach mode first - doesn't need source/dest
    if attach_pid:
        if attach_log:
            manager.log_file = attach_log
        manager.rclone_pid = attach_pid
        manager.transfer_active = True
        return

    if not source or not dest:
        print("Usage: cloudhop <source> <destination> [--flags]")
        print("Example: cloudhop onedrive: gdrive:backup --transfers=8")
        print()
        print("Or just run without arguments for the interactive wizard:")
        print("  cloudhop")
        sys.exit(1)

    manager.set_transfer_paths(source, dest)

    manager.rclone_cmd = [
        "rclone",
        "copy",
        source,
        dest,
        f"--log-file={manager.log_file}",
        "--log-level=INFO",
        "--stats=10s",
        "--stats-log-level=INFO",
    ] + extra_flags

    # Add default transfers if not specified
    if not any(f.startswith("--transfers") for f in extra_flags):
        manager.rclone_cmd.append("--transfers=8")
    if not any(f.startswith("--checkers") for f in extra_flags):
        manager.rclone_cmd.append("--checkers=16")


def _signal_handler(manager: TransferManager) -> None:
    print("\n  CloudHop stopped.")
    if manager.transfer_active:
        print("  (The file transfer continues in the background)")
    print()
    sys.exit(0)
