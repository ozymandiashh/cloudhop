"""CloudMirror CLI entry point."""
import sys
import signal
import platform
import webbrowser
import threading
import http.server

from .server import CloudMirrorHandler, CSRF_TOKEN
from .transfer import TransferManager
from .utils import PORT


def main():
    """Main entry point -- wizard mode (no args) or CLI mode (source dest [flags])."""
    args = sys.argv[1:]
    manager = TransferManager()
    CloudMirrorHandler.manager = manager

    signal.signal(signal.SIGTERM, lambda signum, frame: _signal_handler(manager))

    if len(args) == 0:
        # Web wizard mode
        print()
        print("  +==================================================+")
        print("  |              Welcome to CloudMirror               |")
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
        manager.ensure_rclone()
        parse_cli_args(manager, args)
        print()
        print("  CloudMirror - Advanced Mode")
        print(f"  Command: {' '.join(manager.rclone_cmd)}")
        start_dashboard(manager, start_rclone=True)


def start_dashboard(manager: TransferManager, start_rclone: bool = False):
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
        print("  Starting file transfer...")
        proc = subprocess.Popen(
            manager.rclone_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        manager.rclone_pid = proc.pid
        print(f"  Transfer started (PID {proc.pid})")
        manager.transfer_active = True

    port = manager.port

    print()
    print(f"  CloudMirror: http://localhost:{port}")
    print()
    if manager.transfer_active:
        print("  Open the link above in your browser to monitor progress.")
    else:
        print("  Open the link above in your browser to start the setup wizard.")
    print("  Press Ctrl+C to stop the server.")
    print()

    server = None
    for try_port in range(port, port + 5):
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", try_port), CloudMirrorHandler)
            if try_port != port:
                print(f"  Port {port} was busy, using port {try_port} instead.")
                manager.port = try_port
            break
        except OSError as e:
            if ("Address already in use" in str(e) or e.errno == 48) and try_port < port + 4:
                continue
            if "Address already in use" in str(e) or e.errno == 48:
                print(f"\n  Error: Ports {port}-{port + 4} are all in use.")
                print("  Please stop the other process(es) and try again.\n")
                sys.exit(1)
            raise

    if server is None:
        print(f"\n  Error: Could not bind to any port in range {port}-{port + 4}.\n")
        sys.exit(1)

    # Try to open browser automatically (after port binding succeeds)
    try:
        webbrowser.open(f"http://localhost:{manager.port}")
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _signal_handler(manager)


def parse_cli_args(manager: TransferManager, args):
    """Parse CLI arguments for advanced usage: cloudmirror source: dest: [flags]"""
    source = None
    dest = None
    extra_flags = []

    for arg in args:
        if arg.startswith("--"):
            extra_flags.append(arg)
        elif source is None:
            source = arg
        elif dest is None:
            dest = arg
        else:
            extra_flags.append(arg)

    if not source or not dest:
        print("Usage: cloudmirror <source> <destination> [--flags]")
        print("Example: cloudmirror onedrive: gdrive:backup --transfers=8")
        print()
        print("Or just run without arguments for the interactive wizard:")
        print("  cloudmirror")
        sys.exit(1)

    manager.set_transfer_paths(source, dest)

    manager.rclone_cmd = [
        "rclone", "copy", source, dest,
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


def _signal_handler(manager: TransferManager):
    print("\n  CloudMirror stopped.")
    if manager.transfer_active:
        print("  (The file transfer continues in the background)")
    print()
    sys.exit(0)
