#!/usr/bin/env python3
"""CloudMirror - The easiest way to copy files between cloud storage services."""

import http.server
import re
import os
import sys
import json
import time
import signal
import subprocess
import threading
import secrets
import platform
import shutil
import hashlib
import hmac
import webbrowser
from datetime import datetime, timedelta

CSRF_TOKEN = secrets.token_hex(32)

def validate_rclone_input(value, field_name):
    """Reject inputs that could be interpreted as rclone flags.

    Without this, a malicious wizard input like "--config=/etc/passwd" would be
    passed directly to the rclone subprocess, allowing flag injection attacks.
    Newlines/nulls are rejected to prevent argument splitting.
    """
    if not value:
        return True
    if value.startswith("--") or value.startswith("-"):
        return False
    if "\n" in value or "\r" in value or "\x00" in value:
        return False
    return True


def validate_exclude_pattern(value):
    """Stricter validation for exclude patterns - also rejects shell glob injection chars."""
    if not validate_rclone_input(value, "exclude"):
        return False
    if any(c in value for c in ('{', '}', '[', ']')):
        return False
    return True


def _sanitize_rclone_error(stderr):
    """Convert raw rclone error output to a user-friendly message."""
    if not stderr:
        return "Connection failed. Please try again."
    first_line = stderr.strip().split('\n')[0]
    # Remove timestamp prefix
    if 'ERROR' in first_line or 'NOTICE' in first_line:
        parts = first_line.split(': ', 2)
        first_line = parts[-1] if len(parts) > 1 else first_line
    # Common error translations
    if 'address already in use' in first_line:
        return "Authentication server busy. Please close other rclone processes and try again."
    if 'token' in first_line.lower() or 'oauth' in first_line.lower():
        return "Authentication failed. Please try again."
    if 'timeout' in first_line.lower() or 'timed out' in first_line.lower():
        return "Connection timed out. Please check your internet and try again."
    if len(first_line) > 150:
        return "Connection failed. Please try again."
    return first_line


RE_TRANSFERRED_BYTES = re.compile(r"Transferred:\s+([\d.]+\s+\S+)\s*/\s*([\d.]+\s+\S+),\s*(\d+)%,\s*([\d.]+\s*\S+/s)")
RE_TRANSFERRED_FILES = re.compile(r"Transferred:\s+(\d+)\s*/\s*(\d+),\s*(\d+)%")
RE_ELAPSED = re.compile(r"Elapsed time:\s*(.+)")
RE_ERRORS = re.compile(r"Errors:\s+(\d+)")
RE_SPEED = re.compile(r"([\d.]+)\s*([KMGT]i?B)/s", re.I)
RE_COPIED = re.compile(r"INFO\s+:\s+(.+?):\s+Copied\s+\(new\)")
RE_ACTIVE = re.compile(r"\*\s+(.+?):\s+(\d+)%\s*/(\S+),\s*(\S+/s),\s*(\S+)")
RE_ACTIVE2 = re.compile(r"\*\s+(.+?):\s+(\d+)%\s*/(\S+),\s*(\S+/s)")
RE_ACTIVE3 = re.compile(r"\*\s+(.+?):\s+transferring")
RE_FULL_TRANSFER_ETA = re.compile(r"Transferred:\s+([\d.]+\s+\S+)\s*/\s*([\d.]+\s+\S+),\s*(\d+)%,\s*([\d.]+\s*\S+/s),\s*ETA\s*(\S+)")
RE_CHECKS_LISTED = re.compile(r"Checks:\s+(\d+)\s*/\s*(\d+).+Listed\s+(\d+)")
RE_COPIED_WITH_TS = re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+INFO\s+:\s+(.+?):\s+Copied\s+\(new\)")
RE_ERROR_MSG = re.compile(r"\d{2}:\d{2}:\d{2}\s+ERROR\s+:\s+(.+)")
RE_TIMESTAMP = re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})")
RE_FILES_HIST = re.compile(r"Transferred:\s+(\d+)\s*/\s*\d+,\s*\d+%")

RE_SIZE_VALUE = re.compile(r"([\d.]+)\s*(\S+)")
RE_HOURS = re.compile(r"(\d+)h")
RE_MINUTES = re.compile(r"(\d+)m")
RE_SECONDS = re.compile(r"([\d.]+)s")

_CM_DIR = os.path.join(os.path.expanduser("~"), ".cloudmirror")
os.makedirs(_CM_DIR, mode=0o700, exist_ok=True)
LOG_FILE = os.path.join(_CM_DIR, "cloudmirror.log")
STATE_FILE = os.path.join(_CM_DIR, "cloudmirror_state.json")
PORT = 8787
TRANSFER_LABEL = "Source -> Destination"
LOG_TAIL_BYTES = 16000
RECENT_FILES_INITIAL_CHUNK = 100000
RECENT_FILES_MAX_CHUNK = 2000000
ERROR_TAIL_BYTES = 100000
CHART_DOWNSAMPLE_TARGET = 200
SCANNER_INTERVAL_SEC = 30
MIN_SESSION_ELAPSED_SEC = 300
MAX_REQUEST_BODY_BYTES = 10240
MIN_DOWNTIME_GAP_SEC = 60
RCLONE_SIZE_TIMEOUT_SEC = 600
RCLONE_CONFIG_TIMEOUT_SEC = 120
RCLONE_CHECK_TIMEOUT_SEC = 30
RCLONE_PREVIEW_TIMEOUT_SEC = 60
RCLONE_INSTALL_TIMEOUT_SEC = 120
MAX_TRANSFERS = 64
MAX_HISTORY_ENTRIES = 50000

# rclone command - set dynamically by wizard or CLI args
RCLONE_CMD = []
TRANSFER_ACTIVE = False
rclone_pid = None


def is_rclone_running():
    global rclone_pid
    if rclone_pid:
        try:
            pid, status = os.waitpid(rclone_pid, os.WNOHANG)
            if pid == 0:
                return True  # still running
            rclone_pid = None  # reaped zombie
            return False
        except ChildProcessError:
            # Not our child - fall back to kill check
            try:
                os.kill(rclone_pid, 0)
                return True
            except (ProcessLookupError, OSError):
                rclone_pid = None
        except (ProcessLookupError, OSError):
            rclone_pid = None
    return False


def set_transfer_paths(source, dest):
    """Set unique log/state file paths and transfer label."""
    global LOG_FILE, STATE_FILE, TRANSFER_LABEL
    transfer_id = hashlib.md5(f"{source}:{dest}".encode()).hexdigest()[:8]
    LOG_FILE = os.path.join(_CM_DIR, f"cloudmirror_{transfer_id}.log")
    STATE_FILE = os.path.join(_CM_DIR, f"cloudmirror_{transfer_id}_state.json")
    src_label = get_remote_label(source)
    dst_label = get_remote_label(dest)
    TRANSFER_LABEL = f"{src_label} -> {dst_label}"
    global state
    state = load_state()


def get_remote_label(path):
    """Turn 'onedrive:' into 'OneDrive', 'gdrive:backup' into 'Google Drive'."""
    labels = {
        "protondrive": "Proton Drive",
        "onedrive": "OneDrive",
        "gdrive": "Google Drive", "drive": "Google Drive",
        "dropbox": "Dropbox",
        "s3": "Amazon S3",
        "b2": "Backblaze B2",
        "mega": "MEGA",
        "box": "Box",
        "ftp": "FTP",
        "sftp": "SFTP",
        "local": "Local",
    }
    name = path.split(":")[0].lower().strip()
    for key, label in labels.items():
        if key in name:
            # Add subfolder if present
            subfolder = path.split(":", 1)[1] if ":" in path else ""
            if subfolder:
                return f"{label}/{subfolder}"
            return label
    if ":" not in path or path.startswith("/") or path.startswith("./"):
        return "Local"
    return path.split(":")[0]

# ─── Cloud provider definitions ──────────────────────────────────────────────

PROVIDERS = {
    "1": {"name": "Google Drive", "type": "drive", "key": "gdrive"},
    "2": {"name": "OneDrive", "type": "onedrive", "key": "onedrive"},
    "3": {"name": "Dropbox", "type": "dropbox", "key": "dropbox"},
    "4": {"name": "MEGA", "type": "mega", "key": "mega"},
    "5": {"name": "Amazon S3", "type": "s3", "key": "s3"},
    "6": {"name": "Proton Drive", "type": "protondrive", "key": "protondrive"},
    "7": {"name": "Local folder", "type": "local", "key": "local"},
    "8": {"name": "Other (advanced)", "type": None, "key": None},
}

# ─── Utility: check/install rclone ───────────────────────────────────────────

def find_rclone():
    """Check if rclone is installed and return its path."""
    return shutil.which("rclone")


def install_rclone():
    """Auto-install rclone with user permission."""
    system = platform.system().lower()

    print()
    print("  rclone is not installed on this computer.")
    print("  rclone is the engine that copies files between cloud services.")
    print()

    if system == "windows":
        print("  To install rclone on Windows:")
        print("    1. Go to https://rclone.org/downloads/")
        print("    2. Download the Windows installer")
        print("    3. Run the installer")
        print("    4. Then run CloudMirror again")
        print()
        sys.exit(1)

    answer = input("  Install rclone now? (Y/n): ").strip().lower()
    if answer and answer != "y" and answer != "yes":
        print("  Cannot continue without rclone. Please install it and try again.")
        print("  Visit: https://rclone.org/install/")
        sys.exit(1)

    print()
    print("  Installing rclone...")
    print()

    if system == "darwin":
        # Try brew first
        if shutil.which("brew"):
            print("  Using Homebrew...")
            result = subprocess.run(["brew", "install", "rclone"], capture_output=False)
            if result.returncode == 0 and find_rclone():
                print()
                print("  rclone installed successfully!")
                return find_rclone()

        # Fallback to curl installer
        print("  Downloading from rclone.org...")
        result = subprocess.run(
            ["bash", "-c", "curl -s https://rclone.org/install.sh | sudo bash"],
            capture_output=False,
        )
        if result.returncode == 0 and find_rclone():
            print()
            print("  rclone installed successfully!")
            return find_rclone()

    elif system == "linux":
        print("  Downloading from rclone.org...")
        result = subprocess.run(
            ["bash", "-c", "curl -s https://rclone.org/install.sh | sudo bash"],
            capture_output=False,
        )
        if result.returncode == 0 and find_rclone():
            print()
            print("  rclone installed successfully!")
            return find_rclone()

    print()
    print("  Installation failed. Please install rclone manually:")
    print("  https://rclone.org/install/")
    sys.exit(1)


def ensure_rclone():
    """Make sure rclone is available, install if needed."""
    path = find_rclone()
    if path:
        return path
    return install_rclone()


# ─── Remote configuration ────────────────────────────────────────────────────

def get_existing_remotes():
    """Get list of configured rclone remotes."""
    try:
        result = subprocess.run(
            ["rclone", "listremotes"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            remotes = [r.strip().rstrip(":") for r in result.stdout.strip().split("\n") if r.strip()]
            return remotes
    except Exception:
        pass
    return []


def remote_exists(name):
    """Check if a remote is already configured."""
    return name in get_existing_remotes()


def configure_remote(name, provider_type):
    """Configure an rclone remote interactively."""
    if provider_type == "local":
        return True  # Local paths don't need remote config

    if remote_exists(name):
        print(f"    '{name}' is already configured.")
        return True

    print()
    print(f"    Setting up '{name}' ({provider_type})...")
    print()

    if provider_type in ("drive", "onedrive", "dropbox"):
        print("    A browser window will open.")
        print("    Please log in and authorize CloudMirror.")
        print()
        input("    Press Enter when ready...")
        print()

    # Use rclone config create which handles OAuth automatically
    cmd = ["rclone", "config", "create", name, provider_type]

    # For S3, we need more config - use interactive mode
    if provider_type == "s3":
        print("    For Amazon S3, we need a few more details.")
        print("    Running rclone setup wizard...")
        print()
        result = subprocess.run(["rclone", "config"], capture_output=False)
        return result.returncode == 0

    result = subprocess.run(cmd, capture_output=False)

    if result.returncode == 0:
        print()
        print(f"    '{name}' configured successfully!")
        return True
    else:
        print()
        print(f"    Failed to configure '{name}'. You can set it up manually with:")
        print(f"      rclone config")
        return False


# ─── Persistent state ────────────────────────────────────────────────────────

def load_state():
    """Load persistent state from disk."""
    default = {
        "sessions": [],
        "original_total_bytes": 0,
        "original_total_files": 0,
        "last_elapsed_sec": 0,
        "last_log_offset": 0,
        "cumulative_transferred_bytes": 0,
        "cumulative_files_done": 0,
        "cumulative_elapsed_sec": 0,
        "all_file_types": {},
        "total_copied_count": 0,
        "speed_samples": [],
    }
    try:
        with open(STATE_FILE, "r") as f:
            saved = json.load(f)
            for k, v in default.items():
                if k not in saved:
                    saved[k] = v
            return saved
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_state(state):
    """Save persistent state to disk."""
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"Warning: Could not save state: {e}")


# ─── Byte conversion helpers ─────────────────────────────────────────────────

def to_bytes(size_str):
    """Convert '90.054 GiB' or '103.010 MiB' or '1.5 GB' to bytes."""
    m = RE_SIZE_VALUE.match(size_str.strip())
    if not m:
        return 0
    val = float(m.group(1))
    unit = m.group(2).upper()
    if "GIB" in unit or "GI" in unit:
        return val * 1024 * 1024 * 1024
    elif "MIB" in unit or "MI" in unit:
        return val * 1024 * 1024
    elif "KIB" in unit or "KI" in unit:
        return val * 1024
    elif "TIB" in unit or "TI" in unit:
        return val * 1024 * 1024 * 1024 * 1024
    elif "TB" in unit:
        return val * 1000 * 1000 * 1000 * 1000
    elif "GB" in unit:
        return val * 1000 * 1000 * 1000
    elif "MB" in unit:
        return val * 1000 * 1000
    elif "KB" in unit:
        return val * 1000
    return val


def fmt_bytes(b):
    """Format bytes to human readable."""
    if b >= 1024 ** 4:
        return f"{b / 1024**4:.2f} TiB"
    if b >= 1024 ** 3:
        return f"{b / 1024**3:.2f} GiB"
    if b >= 1024 ** 2:
        return f"{b / 1024**2:.2f} MiB"
    if b >= 1024:
        return f"{b / 1024:.2f} KiB"
    return f"{b:.0f} B"


def parse_elapsed(s):
    """Parse '14h59m30.0s' or '28m0.0s' to seconds."""
    sec = 0
    m = RE_HOURS.findall(s)
    if m:
        sec += int(m[0]) * 3600
    m = RE_MINUTES.findall(s)
    if m:
        sec += int(m[0]) * 60
    m = RE_SECONDS.findall(s)
    if m:
        sec += float(m[0])
    return sec


def fmt_duration(sec):
    """Format seconds to 'Xd Xh Xm Xs'."""
    if sec <= 0:
        return "0s"
    d = int(sec // 86400)
    h = int((sec % 86400) // 3600)
    m = int((sec % 3600) // 60)
    s = int(sec % 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def downsample(arr, target=CHART_DOWNSAMPLE_TARGET):
    """Reduce a list to approximately ``target`` evenly-spaced samples."""
    if len(arr) <= target:
        return arr
    step = len(arr) / target
    out = []
    for i in range(target):
        idx = int(i * step)
        out.append(arr[idx])
    if out and out[-1] != arr[-1]:
        out.append(arr[-1])
    return out


# ─── Log scanner with session detection ──────────────────────────────────────

state_lock = threading.Lock()
_transfer_lock = threading.Lock()
state = load_state()


def scan_full_log():
    """Scan the entire log to detect sessions and build cumulative state.

    Session detection: rclone resets its elapsed timer on each new run.
    We detect a new session when elapsed time drops by >50% (meaning rclone
    restarted). For each session we track bytes transferred, files done,
    and elapsed time. Previous sessions' values are snapshotted *before*
    the drop so we don't lose progress from earlier runs.
    """
    global state
    if not os.path.exists(LOG_FILE):
        return

    # Incremental scanning: on first call read everything, on subsequent
    # calls only read from the last offset and carry forward running state.
    with state_lock:
        last_offset = state.get("last_scan_offset", 0)

    with open(LOG_FILE, "r", errors="replace") as f:
        if last_offset > 0:
            f.seek(last_offset)
        content = f.read()
        new_offset = f.tell()

    # If we seeked to a mid-file offset, we may have landed mid-line.
    # Discard the partial first line to avoid corrupt parsing.
    if last_offset > 0 and content:
        first_nl = content.find('\n')
        if first_nl >= 0:
            content = content[first_nl + 1:]  # skip partial first line
        else:
            content = ''  # entire read was a partial line, skip it

    # If nothing new was written, skip processing.
    if not content and last_offset > 0:
        return

    lines = content.split("\n")

    # Restore running state from previous incremental scans.
    if last_offset > 0:
        with state_lock:
            if not isinstance(state.get("_running_sessions"), list):
                state["_running_sessions"] = []
            sessions = list(state.get("_running_sessions", []))
            current_session = state.get("_running_current_session", None)
            if current_session is not None and not isinstance(current_session, dict):
                current_session = None
            if current_session is not None:
                current_session = dict(current_session)
            prev_elapsed = state.get("_running_prev_elapsed", -1)
            file_types = dict(state.get("all_file_types", {}))
            total_copied_set = set(state.get("_running_copied_files_set", []))
            last_ts = state.get("_running_last_ts", None)
            prev_ts = state.get("_running_prev_ts", None)
            prev_transferred_bytes = state.get("_running_prev_transferred_bytes", 0)
            prev_total_bytes = state.get("_running_prev_total_bytes", 0)
            prev_files_done = state.get("_running_prev_files_done", 0)
            prev_files_total = state.get("_running_prev_files_total", 0)
            # Chart history running state
            speed_hist = list(state.get("_running_speed_hist", []))
            pct_hist = list(state.get("_running_pct_hist", []))
            files_hist = list(state.get("_running_files_hist", []))
            chart_prev_el = state.get("_running_chart_prev_el", -1)
            cumul_bytes_offset = state.get("_running_cumul_bytes_offset", 0)
            cumul_files_offset = state.get("_running_cumul_files_offset", 0)
            session_max_bytes = state.get("_running_session_max_bytes", 0)
            session_max_files = state.get("_running_session_max_files", 0)
            first_session_total = state.get("_running_first_session_total", 0)
            cur_transferred = 0
    else:
        sessions = []
        current_session = None
        prev_elapsed = -1
        file_types = {}
        total_copied_set = set()
        last_ts = None
        prev_ts = None
        prev_transferred_bytes = 0
        prev_total_bytes = 0
        prev_files_done = 0
        prev_files_total = 0
        speed_hist = []
        pct_hist = []
        files_hist = []
        chart_prev_el = -1
        cumul_bytes_offset = 0
        cumul_files_offset = 0
        session_max_bytes = 0
        session_max_files = 0
        first_session_total = 0
        cur_transferred = 0

    # FIX 1: When doing incremental scanning, the first elapsed value in the
    # new chunk should NOT trigger a session boundary because prev_elapsed is
    # stale from the previous chunk and the comparison is meaningless.
    first_elapsed_in_chunk = (last_offset > 0)

    for line in lines:
        ts_match = RE_TIMESTAMP.match(line)
        if ts_match:
            prev_ts = last_ts
            last_ts = ts_match.group(1)

        m_data = RE_TRANSFERRED_BYTES.search(line)
        if m_data:
            cur_transferred = to_bytes(m_data.group(1))
            cur_total = to_bytes(m_data.group(2))
            if current_session is not None:
                prev_transferred_bytes = current_session.get("final_transferred_bytes", 0)
                prev_total_bytes = current_session.get("session_total_bytes", 0)
                current_session["final_transferred_bytes"] = cur_transferred
                current_session["session_total_bytes"] = cur_total
                if last_ts:
                    current_session["last_ts"] = last_ts

            # Chart history: speed and percentage (reuse cur_transferred/cur_total from above)
            if first_session_total == 0:
                first_session_total = cur_total
            session_max_bytes = max(session_max_bytes, cur_transferred)
            if first_session_total > 0:
                global_pct_val = (cumul_bytes_offset + cur_transferred) / first_session_total * 100
                pct_hist.append(round(min(global_pct_val, 100), 1))
            spd_str = m_data.group(4)
            sm = RE_SPEED.match(spd_str)
            if sm:
                v = float(sm.group(1))
                u = sm.group(2).upper()
                if u.startswith("K"): v /= 1024
                elif u.startswith("G"): v *= 1024
                speed_hist.append(round(v, 3))

        m_files = RE_TRANSFERRED_FILES.search(line)
        if m_files:
            if current_session is not None:
                prev_files_done = current_session.get("final_files_done", 0)
                prev_files_total = current_session.get("final_files_total", 0)
                current_session["final_files_done"] = int(m_files.group(1))
                current_session["final_files_total"] = int(m_files.group(2))

        # Chart history: files
        m_fl = RE_FILES_HIST.search(line)
        if m_fl:
            cur_files_chart = int(m_fl.group(1))
            session_max_files = max(session_max_files, cur_files_chart)
            files_hist.append(cumul_files_offset + cur_files_chart)

        m_elapsed = RE_ELAPSED.search(line)
        if m_elapsed:
            elapsed_str = m_elapsed.group(1).strip()
            elapsed_sec = parse_elapsed(elapsed_str)

            # Chart history: session boundary detection for charts
            bytes_changed = abs(cur_transferred - prev_transferred_bytes) > 1_000_000 if cur_transferred else True
            if not first_elapsed_in_chunk and chart_prev_el > MIN_SESSION_ELAPSED_SEC and elapsed_sec < chart_prev_el * 0.5 and bytes_changed:
                cumul_bytes_offset += session_max_bytes
                cumul_files_offset += session_max_files
                session_max_bytes = 0
                session_max_files = 0
                speed_hist.append(None)
                pct_hist.append(None)
                files_hist.append(None)
            chart_prev_el = elapsed_sec

            # Session boundary: elapsed dropped >50% means rclone restarted.
            # Finalize the previous session with its pre-reset values and
            # back-calculate the new session's true start time.
            # Also require transferred bytes changed by >1MB to avoid false boundaries.
            session_bytes_changed = abs(cur_transferred - prev_transferred_bytes) > 1_000_000 if cur_transferred else True
            if not first_elapsed_in_chunk and prev_elapsed > MIN_SESSION_ELAPSED_SEC and elapsed_sec < prev_elapsed * 0.5 and session_bytes_changed:
                if current_session:
                    current_session["end_time"] = current_session.get("last_ts", "")
                    current_session["final_elapsed_sec"] = prev_elapsed
                    current_session["final_transferred_bytes"] = prev_transferred_bytes
                    current_session["session_total_bytes"] = prev_total_bytes
                    current_session["final_files_done"] = prev_files_done
                    current_session["final_files_total"] = prev_files_total
                    sessions.append(current_session)
                new_start = last_ts or ""
                if new_start and elapsed_sec > 0:
                    try:
                        ts_dt = datetime.strptime(new_start, "%Y/%m/%d %H:%M:%S")
                        real_start = ts_dt - timedelta(seconds=elapsed_sec)
                        new_start = real_start.strftime("%Y/%m/%d %H:%M:%S")
                    except Exception:
                        pass
                current_session = {
                    "start_time": new_start,
                    "session_num": len(sessions) + 1,
                    "final_transferred_bytes": 0,
                    "final_files_done": 0,
                    "final_files_total": 0,
                    "final_elapsed_sec": 0,
                    "session_total_bytes": 0,
                }

            if current_session is None:
                first_start = last_ts or ""
                if first_start and elapsed_sec > 0:
                    try:
                        ts_dt = datetime.strptime(first_start, "%Y/%m/%d %H:%M:%S")
                        real_start = ts_dt - timedelta(seconds=elapsed_sec)
                        first_start = real_start.strftime("%Y/%m/%d %H:%M:%S")
                    except Exception:
                        pass
                current_session = {
                    "start_time": first_start,
                    "session_num": 1,
                    "final_transferred_bytes": 0,
                    "final_files_done": 0,
                    "final_files_total": 0,
                    "final_elapsed_sec": 0,
                    "session_total_bytes": 0,
                }

            if last_ts:
                current_session["last_ts"] = last_ts
            current_session["final_elapsed_sec"] = elapsed_sec
            prev_elapsed = elapsed_sec
            first_elapsed_in_chunk = False  # FIX 1: only skip the very first elapsed comparison

        m_copied = RE_COPIED.search(line)
        if m_copied:
            fname = m_copied.group(1).strip()
            total_copied_set.add(fname)
            ext_parts = fname.rsplit(".", 1)
            if len(ext_parts) > 1:
                ext = ext_parts[1].lower()
                file_types[ext] = file_types.get(ext, 0) + 1
            else:
                file_types["other"] = file_types.get("other", 0) + 1

    # For cumulative calculation, build a finalized session list.
    # current_session is kept separately as running state for incremental scans.
    finalized_sessions = list(sessions)
    if current_session:
        cs_copy = dict(current_session)
        cs_copy["end_time"] = cs_copy.get("last_ts", "")
        finalized_sessions.append(cs_copy)

    # FIX 4: Deduplicate sessions with nearly identical start times (within
    # 300 seconds) or sessions that transferred < 1MB (likely false restarts).
    if len(finalized_sessions) > 1:
        deduped = [finalized_sessions[0]]
        for s in finalized_sessions[1:]:
            # Merge sessions that transferred < 1MB (false restarts)
            if s.get("final_transferred_bytes", 0) < 1_000_000 and s is not finalized_sessions[-1]:
                deduped[-1]["end_time"] = s.get("end_time", deduped[-1].get("end_time", ""))
                deduped[-1]["final_elapsed_sec"] = max(
                    deduped[-1].get("final_elapsed_sec", 0),
                    s.get("final_elapsed_sec", 0),
                )
                continue
            prev_start = deduped[-1].get("start_time", "")
            cur_start = s.get("start_time", "")
            if prev_start and cur_start:
                try:
                    t_prev = datetime.strptime(prev_start, "%Y/%m/%d %H:%M:%S")
                    t_cur = datetime.strptime(cur_start, "%Y/%m/%d %H:%M:%S")
                    if abs((t_cur - t_prev).total_seconds()) < 300:
                        # Merge: keep the one with more transferred bytes
                        if s.get("final_transferred_bytes", 0) > deduped[-1].get("final_transferred_bytes", 0):
                            s["start_time"] = deduped[-1].get("start_time", s.get("start_time", ""))
                            s["session_num"] = deduped[-1].get("session_num", s.get("session_num", 0))
                            deduped[-1] = s
                        else:
                            deduped[-1]["end_time"] = s.get("end_time", deduped[-1].get("end_time", ""))
                            deduped[-1]["final_elapsed_sec"] = max(
                                deduped[-1].get("final_elapsed_sec", 0),
                                s.get("final_elapsed_sec", 0),
                            )
                            deduped[-1]["final_transferred_bytes"] = max(
                                deduped[-1].get("final_transferred_bytes", 0),
                                s.get("final_transferred_bytes", 0),
                            )
                            deduped[-1]["final_files_done"] = max(
                                deduped[-1].get("final_files_done", 0),
                                s.get("final_files_done", 0),
                            )
                        continue
                except Exception:
                    pass
            deduped.append(s)
        # Renumber sessions after dedup
        for i, s in enumerate(deduped):
            s["session_num"] = i + 1
        finalized_sessions = deduped
        # Also update the internal sessions list (without the current_session at end)
        if current_session:
            sessions = finalized_sessions[:-1]
        else:
            sessions = finalized_sessions

    cumulative_bytes = 0
    cumulative_files = 0
    cumulative_elapsed = 0
    for s in finalized_sessions[:-1]:
        cumulative_bytes += s.get("final_transferred_bytes", 0)
        cumulative_files += s.get("final_files_done", 0)
        cumulative_elapsed += s.get("final_elapsed_sec", 0)

    # Get the REAL source size by running 'rclone size' once and caching it.
    original_total = 0
    original_files = 0
    with state_lock:
        cached_total = state.get("source_size_bytes", 0)
        cached_files = state.get("source_size_files", 0)
    if cached_total > 0:
        original_total = cached_total
        original_files = cached_files
    elif finalized_sessions:
        original_total = max((s.get("session_total_bytes", 0) or 0) for s in finalized_sessions)
        original_files = max((s.get("final_files_total", 0) or 0) for s in finalized_sessions)
        # Fetch real size in background (only once)
        if not getattr(scan_full_log, '_size_fetching', False):
            scan_full_log._size_fetching = True
            def _fetch_source_size():
                try:
                    src = RCLONE_CMD[2] if len(RCLONE_CMD) > 2 else ""
                    if not src:
                        return
                    sz_result = subprocess.run(
                        ["rclone", "size", src, "--json"],
                        capture_output=True, text=True, timeout=RCLONE_SIZE_TIMEOUT_SEC
                    )
                    if sz_result.returncode == 0:
                        data = json.loads(sz_result.stdout)
                        with state_lock:
                            state["source_size_bytes"] = data.get("bytes", 0)
                            state["source_size_files"] = data.get("count", 0)
                        save_state(state)
                except Exception:
                    pass
                finally:
                    scan_full_log._size_fetching = False
            threading.Thread(target=_fetch_source_size, daemon=True).start()

    # FIX 2: Sanity checks - cumulative values should not exceed source totals.
    if original_files > 0 and cumulative_files > original_files:
        cumulative_files = original_files
    if original_total > 0 and cumulative_bytes > original_total:
        cumulative_bytes = original_total

    # FIX 3: Active time should not exceed wall clock time.
    if finalized_sessions:
        try:
            first_start_str = finalized_sessions[0].get("start_time", "")
            if first_start_str:
                first_start_dt = datetime.strptime(first_start_str, "%Y/%m/%d %H:%M:%S")
                wall_clock_sec = (datetime.now() - first_start_dt).total_seconds()
                if wall_clock_sec > 0 and cumulative_elapsed > wall_clock_sec:
                    cumulative_elapsed = wall_clock_sec
        except Exception:
            pass

    with state_lock:
        state["sessions"] = [
            {
                "num": s.get("session_num", i + 1),
                "start": s.get("start_time", ""),
                "end": s.get("end_time", ""),
                "transferred": s.get("final_transferred_bytes", 0),
                "files": s.get("final_files_done", 0),
                "elapsed_sec": s.get("final_elapsed_sec", 0),
                "session_total": s.get("session_total_bytes", 0),
            }
            for i, s in enumerate(finalized_sessions)
        ]
        state["cumulative_transferred_bytes"] = cumulative_bytes
        state["cumulative_files_done"] = cumulative_files
        state["cumulative_elapsed_sec"] = cumulative_elapsed
        state["original_total_bytes"] = original_total
        state["original_total_files"] = original_files
        state["all_file_types"] = file_types
        state["total_copied_count"] = len(total_copied_set)
        _capped_copied = list(total_copied_set)
        if len(_capped_copied) > 50000:
            _capped_copied = _capped_copied[-50000:]
        state["_running_copied_files_set"] = _capped_copied

        # Cache chart history for parse_current() to read cheaply
        state["cached_speed_history"] = downsample(speed_hist)
        state["cached_pct_history"] = downsample(pct_hist)
        state["cached_files_history"] = downsample(files_hist)

        # Persist incremental scan offset and running state
        state["last_scan_offset"] = new_offset
        state["_running_sessions"] = sessions
        state["_running_current_session"] = current_session
        state["_running_prev_elapsed"] = prev_elapsed
        state["_running_last_ts"] = last_ts
        state["_running_prev_ts"] = prev_ts
        state["_running_prev_transferred_bytes"] = prev_transferred_bytes
        state["_running_prev_total_bytes"] = prev_total_bytes
        state["_running_prev_files_done"] = prev_files_done
        state["_running_prev_files_total"] = prev_files_total
        if len(speed_hist) > MAX_HISTORY_ENTRIES:
            speed_hist = speed_hist[-MAX_HISTORY_ENTRIES:]
        if len(pct_hist) > MAX_HISTORY_ENTRIES:
            pct_hist = pct_hist[-MAX_HISTORY_ENTRIES:]
        if len(files_hist) > MAX_HISTORY_ENTRIES:
            files_hist = files_hist[-MAX_HISTORY_ENTRIES:]
        state["_running_speed_hist"] = speed_hist
        state["_running_pct_hist"] = pct_hist
        state["_running_files_hist"] = files_hist
        state["_running_chart_prev_el"] = chart_prev_el
        state["_running_cumul_bytes_offset"] = cumul_bytes_offset
        state["_running_cumul_files_offset"] = cumul_files_offset
        state["_running_session_max_bytes"] = session_max_bytes
        state["_running_session_max_files"] = session_max_files
        state["_running_first_session_total"] = first_session_total

        save_state(state)



def _parse_tail_stats(tail):
    """Parse the log tail for current transfer stats."""
    result = {
        "speed": None, "eta": None, "session_elapsed": "",
        "session_files_done": 0, "session_files_total": 0,
        "errors": 0, "checks_done": 0, "checks_total": 0, "listed": 0,
    }
    cur_transferred_str = ""
    cur_total_str = ""
    cur_transferred_bytes = 0
    cur_total_bytes = 0

    lines = tail.split("\n")
    for line in lines:
        m = RE_FULL_TRANSFER_ETA.search(line)
        if m:
            cur_transferred_str = m.group(1)
            cur_total_str = m.group(2)
            cur_transferred_bytes = to_bytes(cur_transferred_str)
            cur_total_bytes = to_bytes(cur_total_str)
            result["session_pct"] = int(m.group(3))
            result["speed"] = m.group(4)
            result["eta"] = m.group(5)

        m2 = RE_ERRORS.search(line)
        if m2:
            result["errors"] = int(m2.group(1))

        m3 = RE_TRANSFERRED_FILES.search(line)
        if m3:
            result["session_files_done"] = int(m3.group(1))
            result["session_files_total"] = int(m3.group(2))

        m4 = RE_ELAPSED.search(line)
        if m4:
            result["session_elapsed"] = m4.group(1).strip()

        m5 = RE_CHECKS_LISTED.search(line)
        if m5:
            result["checks_done"] = int(m5.group(1))
            result["checks_total"] = int(m5.group(2))
            result["listed"] = int(m5.group(3))

    return result, cur_transferred_str, cur_total_str, cur_transferred_bytes, cur_total_bytes, lines


def _parse_active_transfers(lines):
    """Parse active transfer items from log lines."""
    active = []
    for line in lines:
        m = RE_ACTIVE.search(line)
        if m:
            active.append({
                "name": m.group(1).strip(),
                "pct": int(m.group(2)),
                "size": m.group(3),
                "speed": m.group(4),
                "eta": m.group(5),
            })
        else:
            m2 = RE_ACTIVE2.search(line)
            if m2:
                active.append({
                    "name": m2.group(1).strip(),
                    "pct": int(m2.group(2)),
                    "size": m2.group(3),
                    "speed": m2.group(4),
                    "eta": "",
                })
            else:
                m3 = RE_ACTIVE3.search(line)
                if m3:
                    active.append({"name": m3.group(1).strip(), "pct": 0, "speed": "", "eta": ""})
    seen = {}
    for t in active:
        seen[t["name"]] = t
    return list(seen.values())


def _parse_recent_files(log_file):
    """Find recently copied files from the log."""
    recent_files = []
    chunk_size = RECENT_FILES_INITIAL_CHUNK
    max_chunk = RECENT_FILES_MAX_CHUNK
    with open(log_file, "rb") as f:
        f.seek(0, 2)
        fsize = f.tell()
        while chunk_size <= max_chunk and len(recent_files) < 15:
            f.seek(max(0, fsize - chunk_size))
            chunk = f.read().decode("utf-8", errors="replace")
            recent_files = []
            for line in chunk.split("\n"):
                m = RE_COPIED_WITH_TS.search(line)
                if m:
                    recent_files.append({"name": m.group(2).strip(), "time": m.group(1).split(" ")[1]})
            if len(recent_files) >= 15 or chunk_size >= fsize:
                break
            chunk_size *= 4
    return recent_files[-15:][::-1]


def _parse_error_messages(log_file):
    """Extract error messages from the log."""
    error_msgs = []
    with open(log_file, "rb") as f:
        f.seek(0, 2)
        fsize = f.tell()
        f.seek(max(0, fsize - ERROR_TAIL_BYTES))
        err_tail = f.read().decode("utf-8", errors="replace")
    for line in err_tail.split("\n"):
        if "ERROR" in line and "Errors:" not in line:
            m = RE_ERROR_MSG.search(line)
            if m:
                msg = m.group(1).strip()
                if msg not in error_msgs:
                    error_msgs.append(msg)
    return error_msgs[-5:]


def parse_current():
    """Parse current stats from the tail of the log, combined with session state.

    This is called every few seconds by the dashboard via /api/status.
    It reads the last 16KB of the log (for current rclone stats), then
    combines those with cumulative session data from scan_full_log() to
    produce global progress numbers that span all sessions.
    """
    if not os.path.exists(LOG_FILE):
        return {"error": "Log file not found", "rclone_running": is_rclone_running()}

    # Read only the tail of the log for current-session stats (fast).
    with open(LOG_FILE, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - LOG_TAIL_BYTES))
        tail = f.read().decode("utf-8", errors="replace")

    result, cur_transferred_str, cur_total_str, cur_transferred_bytes, cur_total_bytes, lines = _parse_tail_stats(tail)
    result["active"] = _parse_active_transfers(lines)
    result["recent_files"] = _parse_recent_files(LOG_FILE)
    result["error_messages"] = _parse_error_messages(LOG_FILE)

    # Process status
    result["finished"] = not is_rclone_running()

    # Speed/progress history from cached state (built by scan_full_log)
    with state_lock:
        result["speed_history"] = state.get("cached_speed_history", [])
        result["pct_history"] = state.get("cached_pct_history", [])
        result["files_history"] = state.get("cached_files_history", [])

    # Combine current session stats with cumulative totals from all prior
    # sessions. global_transferred = prior sessions + current session.
    # For global_total, prefer the cached source size (from rclone size)
    # since rclone's per-session "total" resets and only reflects remaining.
    with state_lock:
        sessions = state.get("sessions", [])
        cumul_bytes = state.get("cumulative_transferred_bytes", 0)
        cumul_files = state.get("cumulative_files_done", 0)
        cumul_elapsed = state.get("cumulative_elapsed_sec", 0)
        orig_total = state.get("original_total_bytes", 0)
        orig_files = state.get("original_total_files", 0)

        global_transferred = cumul_bytes + cur_transferred_bytes

        if orig_total > 0:
            global_total = orig_total
        else:
            global_total = max(cur_total_bytes, cumul_bytes + cur_transferred_bytes)

        if global_transferred > global_total and global_total > 0:
            global_total = global_transferred

        global_files_done = cumul_files + result.get("session_files_done", 0)
        if orig_files > 0:
            global_files_total = orig_files
        else:
            global_files_total = result.get("session_files_total", 0) + cumul_files

        # FIX 2 (parse_current): Cap files/bytes so they never exceed totals
        if global_files_total > 0 and global_files_done > global_files_total:
            global_files_done = global_files_total
        if global_total > 0 and global_transferred > global_total:
            global_transferred = global_total

        session_elapsed_sec = parse_elapsed(result.get("session_elapsed", ""))
        global_elapsed_sec = cumul_elapsed + session_elapsed_sec

        # FIX 3 (parse_current): Cap active time at wall clock time
        if sessions:
            try:
                first_start_pc = datetime.strptime(sessions[0]["start"], "%Y/%m/%d %H:%M:%S")
                wall_sec_pc = (datetime.now() - first_start_pc).total_seconds()
                if wall_sec_pc > 0 and global_elapsed_sec > wall_sec_pc:
                    global_elapsed_sec = wall_sec_pc
            except Exception:
                pass

        global_pct = 0
        if global_total > 0:
            global_pct = round(global_transferred / global_total * 100, 1)
            global_pct = min(global_pct, 100)

        files_pct = 0
        if global_files_total > 0:
            files_pct = round(global_files_done / global_files_total * 100, 1)
            files_pct = min(files_pct, 100)

        result["global_transferred"] = fmt_bytes(global_transferred)
        result["global_transferred_bytes"] = global_transferred
        result["global_total"] = fmt_bytes(global_total)
        result["global_total_bytes"] = global_total
        result["global_pct"] = global_pct
        result["global_files_done"] = global_files_done
        result["global_files_total"] = global_files_total
        result["global_files_pct"] = files_pct
        result["global_elapsed"] = fmt_duration(global_elapsed_sec)
        result["global_elapsed_sec"] = global_elapsed_sec
        result["session_elapsed_sec"] = session_elapsed_sec

        result["session_transferred"] = cur_transferred_str
        result["session_total"] = cur_total_str

        session_num = len(sessions)
        result["session_num"] = session_num
        result["sessions"] = []
        for s in sessions:
            s_start = s.get("start", "")
            s_elapsed = s.get("elapsed_sec", 0)
            s_end = s.get("end", "")
            if s_start and s_elapsed > 0:
                try:
                    real_end = datetime.strptime(s_start, "%Y/%m/%d %H:%M:%S") + timedelta(seconds=s_elapsed)
                    s_end = real_end.strftime("%Y/%m/%d %H:%M:%S")
                except Exception:
                    pass
            result["sessions"].append({
                "num": s.get("num", 0),
                "start": s_start,
                "end": s_end,
                "transferred": fmt_bytes(s.get("transferred", 0)),
                "files": s.get("files", 0),
                "elapsed": fmt_duration(s_elapsed),
                "elapsed_sec": s_elapsed,
            })

        downtimes = []
        for i in range(1, len(sessions)):
            prev_start = sessions[i - 1].get("start", "")
            prev_elapsed = sessions[i - 1].get("elapsed_sec", 0)
            cur_start = sessions[i].get("start", "")
            if prev_start and cur_start:
                try:
                    t_prev_start = datetime.strptime(prev_start, "%Y/%m/%d %H:%M:%S")
                    t_prev_real_end = t_prev_start + timedelta(seconds=prev_elapsed)
                    t_cur_start = datetime.strptime(cur_start, "%Y/%m/%d %H:%M:%S")
                    gap = (t_cur_start - t_prev_real_end).total_seconds()
                    if gap > MIN_DOWNTIME_GAP_SEC:
                        downtimes.append({
                            "after_session": i,
                            "duration": fmt_duration(gap),
                            "duration_sec": gap,
                            "from": t_prev_real_end.strftime("%Y/%m/%d %H:%M:%S"),
                            "to": cur_start,
                        })
                except Exception:
                    pass
        result["downtimes"] = downtimes

        if sessions:
            try:
                first_start = datetime.strptime(sessions[0]["start"], "%Y/%m/%d %H:%M:%S")
                wall_sec = (datetime.now() - first_start).total_seconds()
                result["wall_clock"] = fmt_duration(wall_sec)
                result["wall_clock_sec"] = wall_sec
                if wall_sec > 0:
                    result["uptime_pct"] = round(min(global_elapsed_sec / wall_sec * 100, 100), 1)
                else:
                    result["uptime_pct"] = 0
            except Exception:
                result["wall_clock"] = "--"
                result["uptime_pct"] = 0

        result["all_file_types"] = state.get("all_file_types", {})
        result["total_copied_count"] = state.get("total_copied_count", 0)
        result["transfer_label"] = TRANSFER_LABEL

        daily = {}
        for s in sessions:
            s_start = s.get("start", "")
            s_bytes = s.get("transferred", 0)
            if s_start:
                day = s_start[:10]
                daily[day] = daily.get(day, 0) + s_bytes
        # Sanity check: cap each day's total so it doesn't exceed global transferred
        global_xfer = result.get("global_transferred_bytes", 0)
        if global_xfer > 0:
            for day_key in daily:
                if daily[day_key] > global_xfer:
                    daily[day_key] = global_xfer
        result["daily_stats"] = [
            {"day": d.replace("/", "-"), "bytes": b, "gib": round(b / (1024**3), 1)}
            for d, b in sorted(daily.items())
        ]

    result["rclone_running"] = is_rclone_running()
    return result


# ─── Background log scanner ──────────────────────────────────────────────────

def background_scanner():
    """Periodically rescan the full log to update session state."""
    while True:
        try:
            scan_full_log()
        except Exception as e:
            print(f"Scanner error: {e}")
        time.sleep(SCANNER_INTERVAL_SEC)


# ─── HTML ─────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudMirror Dashboard</title>
<script>(function(){var t=localStorage.getItem('cloudmirror-theme');if(t)document.documentElement.setAttribute('data-theme',t);})()</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ========== CSS VARIABLES ========== */
:root {
  --primary: #6366f1;
  --primary-rgb: 99, 102, 241;
  --secondary: #22d3ee;
  --secondary-rgb: 34, 211, 238;
  --radius: 16px;
  --radius-sm: 10px;
  --section-gap: 28px;
  --card-border: rgba(255,255,255,0.05);
  --transition: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}

[data-theme="dark"] {
  --bg-base: #0b0d13;
  --bg-surface: #12141c;
  --bg-card: #181a24;
  --bg-card-hover: #1e2030;
  --text-primary: #f0f0f5;
  --text-secondary: #8b8fa3;
  --text-tertiary: #5a5e73;
  --border: rgba(255,255,255,0.05);
  --border-hover: rgba(255,255,255,0.1);
  --shadow: 0 1px 3px rgba(0,0,0,0.4);
  --shadow-lg: 0 8px 32px rgba(0,0,0,0.5);
  --noise-opacity: 0.03;
  --chart-grid: rgba(255,255,255,0.05);
  --row-alt: rgba(255,255,255,0.02);
  /* Legacy aliases for JS compatibility */
  --bg: #0b0d13;
  --card: #181a24;
  --card-hover: #1e2030;
  --text: #f0f0f5;
  --text-dim: #8b8fa3;
  --text-muted: #5a5e73;
  --chart-text: #5a5e73;
  --blue: var(--primary);
  --blue-light: #818cf8;
  --green: #22c55e;
  --orange: #f59e0b;
  --red: #ef4444;
  --mini-bar-bg: #12141c;
}

[data-theme="light"] {
  --bg-base: #f3f4f8;
  --bg-surface: #eaebf0;
  --bg-card: #ffffff;
  --bg-card-hover: #f8f8fb;
  --text-primary: #1a1c2b;
  --text-secondary: #6b6f85;
  --text-tertiary: #9b9fb3;
  --border: rgba(0,0,0,0.06);
  --border-hover: rgba(0,0,0,0.12);
  --shadow: 0 1px 3px rgba(0,0,0,0.08);
  --shadow-lg: 0 8px 32px rgba(0,0,0,0.1);
  --noise-opacity: 0.015;
  --chart-grid: rgba(0,0,0,0.06);
  --row-alt: rgba(0,0,0,0.02);
  /* Legacy aliases for JS compatibility */
  --bg: #f3f4f8;
  --card: #ffffff;
  --card-hover: #f8f8fb;
  --text: #1a1c2b;
  --text-dim: #6b6f85;
  --text-muted: #9b9fb3;
  --chart-text: #9b9fb3;
  --blue: var(--primary);
  --blue-light: #818cf8;
  --green: #16a34a;
  --orange: #d97706;
  --red: #dc2626;
  --mini-bar-bg: #eaebf0;
}

/* ========== RESET & BASE ========== */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
*:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }

body {
  font-family: 'DM Sans', -apple-system, sans-serif;
  background: var(--bg-base);
  color: var(--text-primary);
  line-height: 1.5;
  min-height: 100vh;
  transition: background var(--transition), color var(--transition);
  -webkit-font-smoothing: antialiased;
}

/* Noise texture overlay */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  opacity: var(--noise-opacity);
  pointer-events: none;
  z-index: 9999;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  background-size: 200px;
}

.mono { font-family: 'JetBrains Mono', monospace; }

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 24px 60px;
}

.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  transition: background var(--transition), border-color var(--transition), box-shadow var(--transition);
}
.card:hover { border-color: var(--border-hover); }

.section-title {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-tertiary);
  margin-bottom: 16px;
}

/* ========== HEADER ========== */
.header {
  position: sticky;
  top: 0;
  z-index: 100;
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  transition: background var(--transition), border-color var(--transition);
}
.header-inner {
  max-width: 1200px;
  margin: 0 auto;
  padding: 14px 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  position: relative;
}
.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}
.logo {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  display: flex;
  align-items: center;
  justify-content: center;
}
.logo svg { width: 18px; height: 18px; fill: white; }
.logo-text {
  font-weight: 700;
  font-size: 15px;
  color: var(--text-primary);
  letter-spacing: -0.02em;
}

.header-center {
  display: flex;
  align-items: center;
  gap: 10px;
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
}
.transfer-name {
  font-weight: 600;
  font-size: 14px;
  color: var(--text-primary);
  max-width: 40vw;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #22c55e;
  box-shadow: 0 0 8px rgba(34, 197, 94, 0.5);
  flex-shrink: 0;
}
.status-dot.paused { background: #f59e0b; box-shadow: 0 0 8px rgba(245, 158, 11, 0.5); }
.status-dot.error { background: #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.5); }
.status-dot.complete { background: var(--secondary); box-shadow: 0 0 8px rgba(var(--secondary-rgb), 0.5); }
.status-dot.active { animation: pulse 2s infinite; }
.wall-time {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-tertiary);
}

@keyframes pulse {
  0%, 100% { opacity: 1; box-shadow: 0 0 8px rgba(34,197,94,0.5); }
  50% { opacity: 0.6; box-shadow: 0 0 16px rgba(34,197,94,0); }
}
@keyframes ctaGlow {
  0%, 100% { box-shadow: 0 4px 14px rgba(var(--primary-rgb),0.3); }
  50% { box-shadow: 0 4px 24px rgba(var(--primary-rgb),0.6), 0 0 40px rgba(var(--primary-rgb),0.15); }
}

.header-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}
.btn-icon {
  padding: 7px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--bg-card);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all var(--transition);
  display: flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
}
.btn-icon:hover { border-color: var(--border-hover); color: var(--text-primary); }
.btn-icon svg { width: 16px; height: 16px; }

/* Session + status badges (legacy, used by JS) */
.status-badge {
  display: none;
}
.session-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-tertiary);
}

/* ========== BIG PROGRESS ========== */
.progress-section {
  padding: 40px 36px 36px;
  margin-top: var(--section-gap);
  text-align: center;
}
.progress-percentage {
  font-family: 'JetBrains Mono', monospace;
  font-size: 72px;
  font-weight: 700;
  letter-spacing: -0.04em;
  line-height: 1;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.progress-bar-container {
  margin: 24px auto 20px;
  max-width: 600px;
  position: relative;
}
.progress-bar-track {
  height: 8px;
  border-radius: 4px;
  background: var(--bg-surface);
  overflow: hidden;
  position: relative;
}
.progress-bar-fill {
  height: 100%;
  border-radius: 4px;
  background: linear-gradient(90deg, var(--primary), var(--secondary));
  transition: width 2s ease;
  position: relative;
  min-width: 4px;
}
.progress-bar-fill::after {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 4px;
  background: linear-gradient(90deg, transparent 60%, rgba(255,255,255,0.3));
  animation: shimmer 2s infinite;
}
@keyframes shimmer {
  0% { opacity: 0.3; }
  50% { opacity: 0.8; }
  100% { opacity: 0.3; }
}
.progress-glow {
  position: absolute;
  bottom: -6px;
  left: 0;
  height: 16px;
  border-radius: 8px;
  background: linear-gradient(90deg, rgba(var(--primary-rgb),0.3), rgba(var(--secondary-rgb),0.3));
  filter: blur(12px);
  transition: width 2s ease;
  pointer-events: none;
}
.progress-prev {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  border-radius: 4px 0 0 4px;
  background: linear-gradient(90deg, rgba(var(--primary-rgb),0.3), rgba(var(--primary-rgb),0.5));
  opacity: 0.6;
  pointer-events: none;
  transition: width 2s ease;
}
.progress-meta {
  display: flex;
  justify-content: center;
  gap: 32px;
  color: var(--text-secondary);
  font-size: 14px;
}
.progress-meta span { display: flex; align-items: center; gap: 6px; }
.progress-meta .val { color: var(--text-primary); font-family: 'JetBrains Mono', monospace; font-weight: 500; }
.progress-sub-bars {
  display: flex;
  gap: 16px;
  margin-top: 20px;
  max-width: 600px;
  margin-left: auto;
  margin-right: auto;
}
.sub-bar-wrap { flex: 1; }
.sub-bar-label { display: flex; justify-content: space-between; font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; }
.sub-bar-label span { color: var(--text-primary); font-weight: 500; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
.sub-track { height: 6px; background: var(--bg-surface); border-radius: 3px; overflow: hidden; }
.sub-fill { height: 100%; border-radius: 3px; transition: width 2s ease; }
.sub-fill.files { background: linear-gradient(90deg, var(--primary), rgba(var(--primary-rgb),0.7)); }
.sub-fill.checks { background: linear-gradient(90deg, var(--secondary), rgba(var(--secondary-rgb),0.7)); }
.session-note { font-size: 12px; color: var(--text-tertiary); margin-top: 8px; }
.finish-time { font-size: 12px; color: var(--text-tertiary); margin-top: 4px; }

/* ========== CONTROL BAR ========== */
#controlBar {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 20px;
  margin-bottom: 0;
  flex-wrap: wrap;
}
.ctrl-btn {
  padding: 7px 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  font-family: 'DM Sans', sans-serif;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  background: var(--bg-card);
  color: var(--text-secondary);
  letter-spacing: 0.02em;
  min-height: 34px;
  display: flex;
  align-items: center;
  gap: 6px;
}
.ctrl-btn:hover { background: var(--bg-card-hover); border-color: var(--border-hover); color: var(--text-primary); }
.ctrl-btn:active { transform: scale(0.97); }
.ctrl-btn:disabled { opacity: 0.3; cursor: not-allowed; }
.ctrl-btn.pause { color: #f87171; }
.ctrl-btn.pause:hover { color: #fca5a5; }
.ctrl-btn.resume { color: #34d399; }
.ctrl-btn.resume:hover { color: #6ee7b7; }
.ctrl-btn .spinner {
  display: inline-block; width: 10px; height: 10px; border: 2px solid currentColor;
  border-top-color: transparent; border-radius: 50%; animation: spin 0.6s linear infinite;
  margin-right: 4px; vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ========== STATS GRID ========== */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-top: var(--section-gap);
}
.stat-card {
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.stat-card-header {
  display: flex;
  align-items: center;
  gap: 8px;
}
.stat-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.stat-icon.primary { background: rgba(var(--primary-rgb), 0.12); color: var(--primary); }
.stat-icon.secondary { background: rgba(var(--secondary-rgb), 0.12); color: var(--secondary); }
.stat-icon svg { width: 16px; height: 16px; }
.stat-label {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.stat-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 22px;
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: -0.02em;
}
.stat-sub {
  font-size: 12px;
  color: var(--text-tertiary);
}
/* Legacy color classes used by JS */
.stat-value.green, .stat-value.blue, .stat-value.purple, .stat-value.cyan { color: var(--text-primary) !important; }
.stat-value.orange, .stat-value.yellow, .stat-value.pink { color: var(--text-primary) !important; }
.stat-value.red { color: var(--red) !important; }

/* ========== SESSION TIMELINE ========== */
.timeline-section {
  margin-top: var(--section-gap);
  padding: 24px;
}
.timeline-list { display: flex; flex-direction: column; gap: 2px; }
.timeline-item {
  display: grid;
  grid-template-columns: 40px 1fr auto auto;
  gap: 12px;
  align-items: center;
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  transition: background var(--transition);
}
.timeline-item:hover { background: var(--row-alt); }
.tl-num {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-tertiary);
  text-align: center;
}
.tl-time {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-secondary);
}
.tl-duration {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-primary);
  min-width: 60px;
  text-align: right;
}
.tl-label { color: var(--text-secondary); }
.tl-pause-tag {
  color: #f59e0b;
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 4px;
}
.timeline-expand {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 10px;
  margin-top: 8px;
  border-radius: var(--radius-sm);
  border: 1px dashed var(--border);
  color: var(--text-tertiary);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition);
  font-family: 'DM Sans', sans-serif;
  background: none;
  width: 100%;
}
.timeline-expand:hover { color: var(--text-secondary); border-color: var(--border-hover); background: var(--row-alt); }

/* Legacy timeline classes (used by JS) */
.timeline { position: relative; }
.tl-item { position: relative; padding-bottom: 16px; }
.tl-item:last-child { padding-bottom: 0; }
.tl-dot { display: none; }
.tl-header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
.tl-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
.tl-stats { font-size: 12px; color: var(--text-secondary); line-height: 1.6; }
.tl-stats span { color: var(--text-primary); font-weight: 500; font-family: 'JetBrains Mono', monospace; }
.tl-pause { position: relative; padding-bottom: 16px; }
.tl-pause-inner {
  background: rgba(245,158,11,0.05); border: 1px dashed rgba(245,158,11,0.2);
  border-radius: var(--radius-sm); padding: 8px 12px; font-size: 12px; color: var(--orange);
}

/* ========== CHARTS ========== */
.charts-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  margin-top: var(--section-gap);
}
.chart-card {
  padding: 24px;
}
.chart-card-full {
  margin-top: var(--section-gap);
  padding: 24px;
}
.chart-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}
.chart-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}
.chart-container {
  position: relative;
  height: 200px;
  overflow: hidden;
}
.chart-svg { width: 100%; height: 100%; }

/* ========== ACTIVE TRANSFERS ========== */
.active-section {
  margin-top: var(--section-gap);
  padding: 24px;
}
.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.section-header h3 {
  font-size: 13px; font-weight: 600; color: var(--text-tertiary);
  text-transform: uppercase; letter-spacing: 0.08em;
}
.transfer-count {
  font-size: 12px; color: var(--primary);
  background: rgba(var(--primary-rgb),0.1); padding: 2px 10px; border-radius: 10px;
  font-family: 'JetBrains Mono', monospace;
}
.file-list { display: flex; flex-direction: column; }
.file-row {
  display: grid;
  grid-template-columns: 1fr 100px 80px 140px;
  gap: 12px;
  align-items: center;
  padding: 12px 12px;
  border-radius: var(--radius-sm);
  font-size: 13px;
}
.file-row:nth-child(odd) { background: var(--row-alt); }
.file-row:hover { background: rgba(var(--primary-rgb),0.04); }
.file-name {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.file-size {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-secondary);
  text-align: right;
}
.file-speed {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--secondary);
  text-align: right;
}
.file-progress-bar {
  height: 4px;
  border-radius: 2px;
  background: var(--bg-surface);
  overflow: hidden;
}
.file-progress-fill {
  height: 100%;
  border-radius: 2px;
  background: linear-gradient(90deg, var(--primary), var(--secondary));
  transition: width 2s ease;
}

/* Legacy transfer-item classes (used by JS) */
.transfer-item {
  display: grid; grid-template-columns: 1fr 140px 50px 90px 80px;
  align-items: center; gap: 12px; padding: 12px 12px;
  border-radius: var(--radius-sm); margin-bottom: 2px;
  font-size: 13px; transition: background var(--transition);
}
.transfer-item:nth-child(odd) { background: var(--row-alt); }
.transfer-item:hover { background: rgba(var(--primary-rgb),0.04); }
.transfer-item .fname {
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.mini-bar { height: 4px; background: var(--bg-surface); border-radius: 2px; overflow: hidden; }
.mini-fill {
  height: 100%; border-radius: 2px; transition: width 2s ease;
  background: linear-gradient(90deg, var(--primary), var(--secondary));
}
.transfer-item .tpct {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px; font-weight: 600; color: var(--primary); text-align: right;
}
.transfer-item .tspeed {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px; color: var(--secondary); text-align: right;
}
.transfer-item .teta {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px; color: var(--text-secondary); text-align: right;
}

/* ========== BOTTOM ROW ========== */
.bottom-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  margin-top: var(--section-gap);
}
.completed-section { padding: 24px; }
.completed-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  font-size: 13px;
}
.completed-item:nth-child(odd) { background: var(--row-alt); }
.completed-name {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 260px;
}
.completed-size {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-tertiary);
}

/* Legacy recent file classes (used by JS) */
.recent-file {
  display: flex; justify-content: space-between; align-items: center;
  padding: 8px 12px; border-radius: var(--radius-sm);
}
.recent-file:nth-child(odd) { background: var(--row-alt); }
.recent-file .rf-name {
  font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-primary);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; margin-right: 12px;
}
.recent-file .rf-time {
  font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-tertiary); white-space: nowrap;
}
.recent-file .rf-ext { font-size: 11px; padding: 1px 6px; border-radius: 4px; margin-left: 8px; white-space: nowrap; }

.filetypes-section { padding: 24px; }
.filetype-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
  font-size: 13px;
}
.filetype-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-secondary);
  width: 50px;
  flex-shrink: 0;
}
.filetype-bar-track {
  flex: 1;
  height: 18px;
  border-radius: 4px;
  background: var(--bg-surface);
  overflow: hidden;
  position: relative;
}
.filetype-bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.5s ease;
}
.filetype-bar-fill.primary { background: rgba(var(--primary-rgb), 0.6); }
.filetype-bar-fill.secondary { background: rgba(var(--secondary-rgb), 0.5); }
.filetype-count {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-tertiary);
  width: 50px;
  text-align: right;
  flex-shrink: 0;
}

/* Legacy file type classes (used by JS) */
.types-grid { display: flex; flex-direction: column; gap: 10px; margin-top: 8px; }
.type-badge {
  display: flex; align-items: center; gap: 12px; padding: 0;
  border-radius: 0; background: none; font-size: 13px;
}
.type-badge .type-name {
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: var(--text-secondary); width: 50px; flex-shrink: 0;
}
.type-badge .type-count {
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  color: var(--text-tertiary); width: 50px; text-align: right; flex-shrink: 0;
}
.type-bar {
  flex: 1; height: 18px; border-radius: 4px;
  min-width: 12px; max-width: none;
}

/* ========== ERROR ========== */
.error-section {
  background: rgba(239,68,68,0.05); border: 1px solid rgba(239,68,68,0.15);
  border-radius: var(--radius); padding: 16px 24px; margin-top: var(--section-gap); display: none;
}
.error-section.show { display: block; }
.error-section h3 {
  font-size: 13px; font-weight: 600; color: var(--red);
  text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px;
}
.error-item {
  font-size: 12px; color: var(--red); padding: 4px 0;
  font-family: 'JetBrains Mono', monospace;
  word-break: break-all;
}

/* ========== DAILY CHART ========== */
.daily-chart-section {
  margin-top: var(--section-gap);
  padding: 24px;
  display: none;
}

/* ========== FOOTER ========== */
.footer {
  margin-top: var(--section-gap);
  padding: 20px 0;
  text-align: center;
  font-size: 12px;
  color: var(--text-tertiary);
  border-top: 1px solid var(--border);
}
.footer a { color: var(--primary); text-decoration: none; }
.footer a:hover { text-decoration: underline; }

/* ========== TOAST ========== */
.toast {
  position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius-sm); padding: 10px 20px; font-size: 13px;
  color: var(--text-primary); z-index: 200; opacity: 0; transition: opacity 0.3s;
  pointer-events: none; box-shadow: var(--shadow-lg);
}
.toast.show { opacity: 1; }

/* ========== SCROLLBAR ========== */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--border-hover); }

/* ========== RESPONSIVE ========== */
@media (max-width: 768px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .charts-row, .bottom-row { grid-template-columns: 1fr; }
  .header-center { position: static; transform: none; }
  .header-inner { flex-wrap: wrap; }
  .progress-percentage { font-size: 48px; }
  .file-row { grid-template-columns: 1fr 80px 120px; }
  .file-speed { display: none; }
  .transfer-item { grid-template-columns: 1fr 80px 40px 60px; gap: 6px; padding: 8px 6px; }
  .transfer-item .teta { display: none; }
  .progress-sub-bars { flex-direction: column; }
}
</style>
</head>
<body>

<!-- ========== HEADER ========== -->
<header class="header">
  <div class="header-inner">
    <div class="header-left">
      <div class="logo">
        <svg width="24" height="24" viewBox="0 0 64 64" fill="none">
    <path d="M48 28c0-8.8-7.2-16-16-16-6.5 0-12.1 3.9-14.6 9.5C16.5 21.2 15.8 21 15 21c-3.3 0-6 2.7-6 6 0 .4 0 .8.1 1.1C5.5 29.5 3 33.2 3 37.5 3 43 7.5 47.5 13 47.5h35c4.4 0 8-3.6 8-8s-3.6-8-8-8c-.3 0-.7 0-1 .1.6-1.1 1-2.3 1-3.6z" fill="#6366f1"/>
    <path d="M22 36h20M38 31l5 5-5 5" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
      </div>
      <span class="logo-text" id="transferTitle">CloudMirror</span>
    </div>
    <div class="header-center">
      <div class="status-dot" id="statusDot"></div>
      <span class="transfer-name" id="statusText">Loading...</span>
      <span class="wall-time mono" id="wallClock">--</span>
    </div>
    <div class="header-right">
      <span class="session-badge" id="sessionBadge">Session 1</span>
      <button class="btn-icon ctrl-btn pause" id="btnPause" onclick="doAction('pause')" title="Pause transfer" aria-label="Pause transfer">
        <svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
      </button>
      <button class="btn-icon ctrl-btn resume" id="btnResume" onclick="doAction('resume')" style="display:none" title="Resume transfer" aria-label="Resume transfer">
        <svg viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
      </button>
      <button class="btn-icon" id="btnCancel" onclick="cancelTransfer()" title="Cancel transfer" aria-label="Cancel transfer">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
      <a href="/wizard" class="btn-icon" id="btnNewTransfer" title="New Transfer" aria-label="New Transfer" style="text-decoration:none;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
      </a>
      <button class="btn-icon" id="themeToggle" onclick="toggleTheme()" title="Toggle theme" aria-label="Toggle theme">
        <svg id="theme-icon-dark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
        <svg id="theme-icon-light" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </button>
    </div>
  </div>
</header>

<!-- Hidden legacy elements for JS compatibility -->
<div class="status-badge" id="statusBadge" style="display:none"><div class="status-dot"></div><span></span></div>

<div class="container">

<!-- ========== EMPTY STATE ========== -->
<div id="emptyState" style="display:none;text-align:center;padding:80px 20px;">
  <div style="margin-bottom:16px;opacity:0.5;">
    <svg width="48" height="48" viewBox="0 0 64 64" fill="none">
    <path d="M48 28c0-8.8-7.2-16-16-16-6.5 0-12.1 3.9-14.6 9.5C16.5 21.2 15.8 21 15 21c-3.3 0-6 2.7-6 6 0 .4 0 .8.1 1.1C5.5 29.5 3 33.2 3 37.5 3 43 7.5 47.5 13 47.5h35c4.4 0 8-3.6 8-8s-3.6-8-8-8c-.3 0-.7 0-1 .1.6-1.1 1-2.3 1-3.6z" fill="#6366f1"/>
    <path d="M22 36h20M38 31l5 5-5 5" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
  </div>
  <div style="font-size:1.3rem;font-weight:700;color:var(--text-primary);margin-bottom:8px;">No active transfer</div>
  <div style="font-size:0.9rem;color:var(--text-secondary);margin-bottom:24px;">Set up a new transfer to start copying files between cloud services.</div>
  <a href="/wizard" style="display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:14px 32px;border-radius:12px;font-size:1rem;font-weight:600;background:linear-gradient(135deg,var(--primary),var(--secondary));color:#fff;text-decoration:none;animation:ctaGlow 2s ease-in-out infinite;">Start New Transfer</a>
</div>

<!-- ========== BIG PROGRESS ========== -->
<div class="progress-section card" id="dashboardContent">
  <div class="progress-percentage mono"><span id="bigPct">0</span>%</div>
  <div class="progress-bar-container">
    <div class="progress-bar-track">
      <div class="progress-prev" id="prevBar" style="width:0%"></div>
      <div class="progress-bar-fill" id="bigBar" style="width:0%" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
    </div>
    <div class="progress-glow" id="progressGlow" style="width:0%"></div>
  </div>
  <div class="progress-meta">
    <span>Transferred <span class="val" id="bpTransferred">--</span> / <span class="val" id="bpTotal">--</span></span>
    <span>ETA <span class="val" id="bpEta">--</span></span>
  </div>
  <div class="finish-time" id="finishTime"></div>
  <div class="session-note" id="sessionNote"></div>
  <div class="progress-sub-bars">
    <div class="sub-bar-wrap">
      <div class="sub-bar-label">
        <span>Files</span>
        <span><span id="filesDone">0</span> / <span id="filesTotal">0</span> (<span id="filesPct">0</span>%)</span>
      </div>
      <div class="sub-track"><div class="sub-fill files" id="filesBar" style="width:0%"></div></div>
    </div>
    <div class="sub-bar-wrap">
      <div class="sub-bar-label">
        <span>Checks</span>
        <span><span id="checksDone">0</span> / <span id="checksTotal">0</span></span>
      </div>
      <div class="sub-track"><div class="sub-fill checks" id="checksBar" style="width:0%"></div></div>
    </div>
  </div>
</div>

<!-- ========== CONTROL BAR ========== -->
<div id="controlBar" style="display:flex;align-items:center;justify-content:center;gap:8px;margin:12px auto;max-width:1200px;padding:0 24px;flex-wrap:wrap;">
  <button class="btn-icon ctrl-btn pause" id="btnPause2" onclick="doAction('pause')" title="Pause transfer" aria-label="Pause transfer">
    <svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Pause
  </button>
  <button class="btn-icon ctrl-btn resume" id="btnResume2" onclick="doAction('resume')" style="display:none" title="Resume transfer" aria-label="Resume transfer">
    <svg viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg> Resume
  </button>
  <button class="btn-icon" id="btnCancel2" onclick="cancelTransfer()" title="Cancel transfer" aria-label="Cancel transfer">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Cancel
  </button>
  <a href="/wizard" class="btn-icon" id="btnNewTransfer2" title="New Transfer" aria-label="New Transfer" style="text-decoration:none;">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> New Transfer
  </a>
</div>

<!-- ========== STATS GRID ========== -->
<div class="stats-grid" id="statsGrid">
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon primary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      </div>
      <span class="stat-label">Current Speed</span>
    </div>
    <div class="stat-value green" id="speed">--</div>
    <div class="stat-sub" id="speedSub">--</div>
  </div>
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon secondary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>
      </div>
      <span class="stat-label">Avg Speed</span>
    </div>
    <div class="stat-value blue" id="avgSpeed">--</div>
    <div class="stat-sub" id="avgSpeedSub">across all sessions</div>
  </div>
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon primary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
      </div>
      <span class="stat-label">Peak Speed</span>
    </div>
    <div class="stat-value purple" id="peakSpeed">--</div>
    <div class="stat-sub" id="peakTime">--</div>
  </div>
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon secondary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      </div>
      <span class="stat-label">Active Time</span>
    </div>
    <div class="stat-value cyan" id="elapsed">--</div>
    <div class="stat-sub" id="elapsedSub">this session: --</div>
  </div>
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon secondary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
      </div>
      <span class="stat-label">Files/min</span>
    </div>
    <div class="stat-value orange" id="filesRate">--</div>
    <div class="stat-sub" id="filesRateSub">--</div>
  </div>
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon primary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      </div>
      <span class="stat-label">Files Copied</span>
    </div>
    <div class="stat-value yellow" id="totalCopied">--</div>
    <div class="stat-sub" id="totalCopiedSub">all sessions</div>
  </div>
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon primary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </div>
      <span class="stat-label">Total Downtime</span>
    </div>
    <div class="stat-value pink" id="downtime">--</div>
    <div class="stat-sub" id="downtimeSub">--</div>
  </div>
  <div class="stat-card card">
    <div class="stat-card-header">
      <div class="stat-icon secondary">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      </div>
      <span class="stat-label">Errors</span>
    </div>
    <div class="stat-value" id="errors" style="color:var(--green)">0</div>
    <div class="stat-sub" id="errorSub">none</div>
  </div>
</div>

<!-- ========== SESSION TIMELINE ========== -->
<div class="timeline-section card" id="timelineSection" style="display:none">
  <div class="section-title" style="cursor:pointer;user-select:none;" onclick="toggleTimeline()">Session Timeline <span id="tlToggle" style="font-size:0.65rem;color:var(--text-tertiary);margin-left:6px;">&#9660;</span></div>
  <div class="timeline" id="timeline"></div>
</div>

<!-- ========== CHARTS ROW ========== -->
<div class="charts-row" id="chartsRow">
  <div class="chart-card card">
    <div class="chart-header">
      <span class="chart-title">Transfer Speed</span>
    </div>
    <div class="chart-container"><svg class="chart-svg" id="speedChart" aria-label="Speed chart"></svg></div>
  </div>
  <div class="chart-card card">
    <div class="chart-header">
      <span class="chart-title">Data Progress</span>
    </div>
    <div class="chart-container"><svg class="chart-svg" id="progressChart" aria-label="Data progress chart"></svg></div>
  </div>
</div>

<!-- ========== FILES CHART ========== -->
<div class="chart-card-full card" id="chartsFullRow">
  <div class="chart-header">
    <span class="chart-title">Files Transferred Over Time</span>
  </div>
  <div class="chart-container"><svg class="chart-svg" id="filesChart" aria-label="Files transferred chart"></svg></div>
</div>

<!-- ========== DAILY VOLUME ========== -->
<div class="chart-card card daily-chart-section" id="dailyChartSection">
  <div class="chart-header">
    <span class="chart-title">Daily Transfer Volume</span>
  </div>
  <div id="dailyBars" style="display:flex;align-items:flex-end;gap:8px;height:120px;padding-top:12px;"></div>
</div>

<!-- ========== ERRORS ========== -->
<div class="error-section" id="errorSection">
  <h3>Errors</h3>
  <div id="errorList"></div>
</div>

<!-- ========== ACTIVE TRANSFERS ========== -->
<div class="active-section card" id="transfersSection">
  <div class="section-header">
    <h3>Active Transfers</h3>
    <div class="transfer-count" id="transferCount">0 active</div>
  </div>
  <div id="transfersList"></div>
</div>

<!-- ========== BOTTOM ROW ========== -->
<div class="bottom-row" id="recentSection">
  <div class="completed-section card">
    <div class="section-title">Recently Completed</div>
    <div id="recentFiles"></div>
  </div>
  <div class="filetypes-section card">
    <div class="section-title">File Types</div>
    <div id="fileTypes"></div>
  </div>
</div>

<!-- ========== FOOTER ========== -->
<footer class="footer" id="footer">
  CloudMirror Dashboard &middot; Auto-refresh 5s &middot; <span id="footerInfo">--</span> &middot; Uptime: <span id="uptimePct">--</span> &middot; Updated: <span id="lastUpdate">--</span> &middot; <a href="#" onclick="showHistory();return false;">Transfer History</a>
</footer>

</div>

<div class="toast" id="toast" role="status" aria-live="polite"></div>
<div id="connLost" role="alert" aria-live="assertive" style="display:none;position:fixed;top:0;left:0;right:0;background:var(--red);color:#fff;text-align:center;padding:10px 16px;font-size:0.85rem;font-weight:600;z-index:300;">Connection lost. Dashboard cannot reach the server.</div>

<script>
function getCsrfToken(){return document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith('csrf_token='))?.substring('csrf_token='.length)||''}
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

let failCount = 0;
let speedHistory = [];
let progressHistory = [];
let filesHistory = [];
let historyLoaded = false;

// Styled confirm modal (replaces native confirm())
function showConfirmModal(message) {
  return new Promise((resolve) => {
    if (document.getElementById('_cm_overlay')) return resolve(false);
    const overlay = document.createElement('div');
    overlay.id = '_cm_overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:9999;';
    overlay.innerHTML = `<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:28px 32px;max-width:420px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.3);"><p style="margin:0 0 20px;font-size:0.95rem;color:var(--text-primary);">${message.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</p><div style="display:flex;gap:10px;justify-content:flex-end;"><button id="_cm_cancel" style="padding:8px 18px;border-radius:8px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-primary);cursor:pointer;">Cancel</button><button id="_cm_ok" style="padding:8px 18px;border-radius:8px;border:none;background:var(--primary);color:#fff;cursor:pointer;font-weight:600;">OK</button></div></div>`;
    document.body.appendChild(overlay);
    function cleanup() { overlay.remove(); document.removeEventListener('keydown', escHandler); }
    function escHandler(e) { if (e.key === 'Escape') { cleanup(); resolve(false); } }
    document.addEventListener('keydown', escHandler);
    overlay.querySelector('#_cm_ok').onclick = () => { cleanup(); resolve(true); };
    overlay.querySelector('#_cm_cancel').onclick = () => { cleanup(); resolve(false); };
    overlay.addEventListener('click', (e) => { if (e.target === overlay) { cleanup(); resolve(false); } });
    overlay.querySelector('#_cm_ok').focus();
  });
}
let peakSpeedVal = 0;
let peakSpeedTime = '';

function parseSpeed(str) {
  if (!str) return 0;
  const m = str.match(/([\d.]+)\s*([KMGT]i?B)\/s/i);
  if (!m) return 0;
  let val = parseFloat(m[1]);
  const u = m[2].toUpperCase();
  if (u.startsWith('K')) val /= 1024;
  else if (u.startsWith('G')) val *= 1024;
  else if (u.startsWith('T')) val *= 1024 * 1024;
  return val;
}

function fmtSpeed(mbs) {
  if (mbs === 0) return '--';
  if (mbs < 1) return (mbs * 1024).toFixed(0) + ' KiB/s';
  if (mbs >= 1024) return (mbs / 1024).toFixed(2) + ' GiB/s';
  return mbs.toFixed(2) + ' MiB/s';
}

function fmtEta(eta) {
  if (!eta || eta === '--') return '--';
  return eta.replace(/(\d+)d/, '$1d ').replace(/(\d+)h/, '$1h ').replace(/(\d+)m/, '$1m');
}

function fmtDuration(sec) {
  if (!sec || sec <= 0) return 'none';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  let r = '';
  if (d) r += d + 'd ';
  if (h) r += h + 'h ';
  if (m) r += m + 'm ';
  if (!r && s) r += s + 's';
  return r.trim() || 'none';
}

function drawAreaChart(svgId, data, color, gradId, formatY, minZero, maxCap) {
  const svg = document.getElementById(svgId);
  if (!svg) return;
  const cs = getComputedStyle(document.documentElement);
  const cGrid = cs.getPropertyValue('--chart-grid').trim() || '#151d35';
  const cText = cs.getPropertyValue('--chart-text').trim() || '#2a3555';
  const w = svg.clientWidth || 500;
  const h = svg.clientHeight || 140;
  // Skip redraw if data and dimensions unchanged
  const dataKey = svgId + w + 'x' + h + JSON.stringify(data.slice(-5));
  if (drawAreaChart._cache && drawAreaChart._cache[svgId] === dataKey) return;
  if (!drawAreaChart._cache) drawAreaChart._cache = {};
  drawAreaChart._cache[svgId] = dataKey;
  const realData = data.filter(v => v !== null);
  if (realData.length < 2) {
    const emptyColor = cs.getPropertyValue('--text-secondary').trim() || '#6b7280';
    svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="${emptyColor}" font-size="12" font-family="DM Sans, sans-serif">Collecting data...</text>`;
    return;
  }
  const pad = { t: 12, b: 20, l: 52, r: 12 };
  const cw = w - pad.l - pad.r;
  const ch = h - pad.t - pad.b;

  const dataMax = Math.max(...realData);
  const dataMin = minZero ? 0 : Math.min(...realData);
  let rangeMax = dataMax + (dataMax - dataMin) * 0.1;
  if (maxCap !== undefined) rangeMax = Math.min(rangeMax, maxCap);
  let rangeMin = minZero ? 0 : Math.max(0, dataMin - (dataMax - dataMin) * 0.1);
  if (rangeMax === rangeMin) { rangeMax = rangeMin + 1; }

  function niceNum(range, round) {
    const exp = Math.floor(Math.log10(range));
    const frac = range / Math.pow(10, exp);
    let nice;
    if (round) {
      if (frac < 1.5) nice = 1;
      else if (frac < 3) nice = 2;
      else if (frac < 7) nice = 5;
      else nice = 10;
    } else {
      if (frac <= 1) nice = 1;
      else if (frac <= 2) nice = 2;
      else if (frac <= 5) nice = 5;
      else nice = 10;
    }
    return nice * Math.pow(10, exp);
  }

  const range = rangeMax - rangeMin;
  const tickSpacing = niceNum(range / 4, true);
  const niceMin = Math.floor(rangeMin / tickSpacing) * tickSpacing;
  const niceMax = Math.ceil(rangeMax / tickSpacing) * tickSpacing;

  let html = `<defs><linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="${color}" stop-opacity="0.25"/>
    <stop offset="100%" stop-color="${color}" stop-opacity="0.02"/>
  </linearGradient></defs>`;

  for (let tick = niceMin; tick <= niceMax; tick += tickSpacing) {
    const y = pad.t + ch - ((tick - niceMin) / (niceMax - niceMin)) * ch;
    html += `<line x1="${pad.l}" y1="${y}" x2="${w - pad.r}" y2="${y}" stroke="${cGrid}" stroke-width="1"/>`;
    html += `<text x="${pad.l - 6}" y="${y + 3}" text-anchor="end" fill="${cText}" font-size="9" font-family="JetBrains Mono, monospace">${formatY ? formatY(tick) : tick.toFixed(1)}</text>`;
  }

  const maxVal = niceMax;
  const minVal = niceMin;

  let segments = [];
  let current = [];
  data.forEach((v, i) => {
    if (v === null) {
      if (current.length > 0) { segments.push(current); current = []; }
    } else {
      current.push({ v, i });
    }
  });
  if (current.length > 0) segments.push(current);

  segments.forEach(seg => {
    if (seg.length < 2) return;
    const pts = seg.map(p => {
      const x = pad.l + (p.i / (data.length - 1)) * cw;
      const y = pad.t + ch - ((p.v - minVal) / (maxVal - minVal)) * ch;
      return `${x},${y}`;
    });
    const area = [...pts, `${pad.l + (seg[seg.length-1].i / (data.length-1)) * cw},${pad.t+ch}`, `${pad.l + (seg[0].i / (data.length-1)) * cw},${pad.t+ch}`];
    html += `<polygon points="${area.join(' ')}" fill="url(#${gradId})"/>`;
    html += `<polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
  });

  for (let i = 0; i < segments.length - 1; i++) {
    const last = segments[i][segments[i].length - 1];
    const first = segments[i + 1][0];
    const x1 = pad.l + (last.i / (data.length - 1)) * cw;
    const y1 = pad.t + ch - ((last.v - minVal) / (maxVal - minVal)) * ch;
    const x2 = pad.l + (first.i / (data.length - 1)) * cw;
    const y2 = pad.t + ch - ((first.v - minVal) / (maxVal - minVal)) * ch;
    html += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="1" stroke-dasharray="4,4" opacity="0.3"/>`;
  }

  const lastSeg = segments[segments.length - 1];
  if (lastSeg && lastSeg.length > 0) {
    const last = lastSeg[lastSeg.length - 1];
    const lx = pad.l + (last.i / (data.length - 1)) * cw;
    const ly = pad.t + ch - ((last.v - minVal) / (maxVal - minVal)) * ch;
    html += `<circle cx="${lx}" cy="${ly}" r="3.5" fill="${color}" stroke="${cs.getPropertyValue('--bg-card').trim()}" stroke-width="2"/>`;
    html += `<text x="${w-pad.r}" y="${h-3}" text-anchor="end" fill="${cText}" font-size="9" font-family="JetBrains Mono, monospace">${formatY ? formatY(last.v) : last.v.toFixed(2)}</text>`;
  }

  svg.innerHTML = html;
}

const typeColors = {
  pdf:'#ef4444',mp4:'#3b82f6',key:'#f59e0b',docx:'#22c55e',xlsx:'#a78bfa',
  png:'#f472b6',jpg:'#fb923c',zip:'#22d3ee',oas:'#818cf8',pptx:'#34d399',
  mov:'#60a5fa',avi:'#c084fc',doc:'#4ade80',txt:'#fbbf24',other:'#475569'
};
function getTypeColor(ext) { return typeColors[ext] || typeColors.other; }
function getExtension(fn) { const p=fn.split('.'); return p.length>1?p[p.length-1].toLowerCase():'other'; }

function friendlyError(msg) {
    const map = [
        [/403.*rate/i, 'Google Drive rate limit reached. Transfer will resume automatically.'],
        [/429/i, 'Too many requests. Slowing down automatically.'],
        [/quota/i, 'Storage quota exceeded. Free up space on the destination.'],
        [/token.*expired/i, 'Authentication expired. Please reconnect your account.'],
        [/no such host/i, 'Network error. Check your internet connection.'],
        [/permission denied/i, 'Permission denied. Check your account access.'],
        [/not found/i, 'File or folder not found. It may have been moved or deleted.'],
    ];
    for (const [pattern, friendly] of map) {
        if (pattern.test(msg)) return friendly;
    }
    return msg;
}

// Update header status dot appearance
function updateStatusDot(state) {
  const dot = document.getElementById('statusDot');
  if (!dot) return;
  dot.className = 'status-dot';
  dot.style.animation = '';
  dot.style.background = '';
  dot.style.boxShadow = '';
  if (state === 'active') {
    dot.classList.add('active');
    dot.style.background = '#22c55e';
    dot.style.boxShadow = '0 0 8px rgba(34,197,94,0.5)';
  } else if (state === 'paused') {
    dot.classList.add('paused');
  } else if (state === 'error' || state === 'stopped') {
    dot.classList.add('error');
  } else if (state === 'complete') {
    dot.classList.add('complete');
  } else {
    dot.style.background = 'var(--text-tertiary)';
    dot.style.boxShadow = 'none';
  }
}

async function refresh() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const d = await res.json();
    failCount = 0;
    document.getElementById('connLost').style.display = 'none';
    document.querySelector('.header').style.top = '0';
    document.body.style.paddingTop = '';

    // Show empty state if API returns error (no log file) AND rclone is NOT running
    if (d.error && !d.rclone_running) {
      document.getElementById('emptyState').style.display = 'block';
      ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
      });
      ['btnPause','btnResume','btnCancel','btnNewTransfer','sessionBadge','btnPause2','btnResume2','btnCancel2','btnNewTransfer2'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
      });
      { const cb = document.getElementById('controlBar'); if (cb) cb.style.display = 'none'; }
      updateStatusDot('idle');
      document.getElementById('statusText').textContent = 'Idle';
      return;
    }
    // If rclone is running but log not ready yet, show Starting state
    if (d.error && d.rclone_running) {
      document.getElementById('emptyState').style.display = 'none';
      ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
      });
      ['btnPause','btnResume','btnCancel','btnNewTransfer','sessionBadge'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
      });
      { const cb = document.getElementById('controlBar'); if (cb) cb.style.display = 'flex'; }
      updateStatusDot('active');
      document.getElementById('statusText').textContent = 'Starting...';
      return;
    }

    // Status
    if (d.finished && d.global_pct >= 100) {
      updateStatusDot('complete');
      document.getElementById('statusText').textContent = 'Complete';
      updateButtons(false);
      if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = setInterval(refresh, 30000); }
    } else if (d.rclone_running && !d.speed && !d.session_num) {
      updateStatusDot('active');
      document.getElementById('statusText').textContent = 'Starting...';
      updateButtons(true);
    } else if (d.finished && !d.rclone_running && d.global_pct < 100) {
      updateStatusDot('stopped');
      document.getElementById('statusText').textContent = 'Stopped';
      updateButtons(false);
    } else if (d.finished) {
      updateStatusDot('paused');
      document.getElementById('statusText').textContent = 'Paused';
      updateButtons(false);
    } else if (!d.speed && !d.session_num) {
      updateStatusDot('idle');
      document.getElementById('statusText').textContent = 'Idle';
      updateButtons(false);
    } else {
      updateStatusDot('active');
      document.getElementById('statusText').textContent = 'Transferring';
      updateButtons(true);
      if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = setInterval(refresh, 5000); }
    }

    // Empty state: show when truly no transfer (not running, no data)
    const isEmpty = !d.rclone_running && !d.session_num && (d.global_total_bytes === undefined || d.global_total_bytes === 0) && !d.speed;
    document.getElementById('emptyState').style.display = isEmpty ? 'block' : 'none';
    ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = isEmpty ? 'none' : '';
    });
    ['btnPause','btnResume','btnCancel','btnNewTransfer','sessionBadge','btnPause2','btnResume2','btnCancel2','btnNewTransfer2'].forEach(id => {
      const el = document.getElementById(id);
      if (el && isEmpty) el.style.display = 'none';
    });
    {const cb=document.getElementById('controlBar');if(cb)cb.style.display=isEmpty?'none':'flex';}
    if (isEmpty) return;

    // Session badge
    document.getElementById('sessionBadge').textContent = `Session ${d.session_num || 1}`;
    if (d.transfer_label) document.getElementById('transferTitle').textContent = d.transfer_label;

    if (d.speed_history && d.speed_history.length > 0) {
      speedHistory = d.speed_history;
    }
    if (d.pct_history && d.pct_history.length > 0) {
      progressHistory = d.pct_history;
    }
    if (d.files_history && d.files_history.length > 0) {
      filesHistory = d.files_history;
    }

    // Wall clock + uptime
    if (d.wall_clock) document.getElementById('wallClock').textContent = d.wall_clock;
    const uptimeEl = document.getElementById('uptimePct');
    if (d.uptime_pct !== undefined && uptimeEl) uptimeEl.textContent = d.uptime_pct + '%';

    // Big progress - GLOBAL
    const pct = d.global_pct || 0;
    document.getElementById('bigPct').textContent = pct;
    document.getElementById('bigBar').style.width = Math.max(pct, 0.2) + '%';
    document.getElementById('bigBar').setAttribute('aria-valuenow', pct);
    const glowEl = document.getElementById('progressGlow');
    if (glowEl) glowEl.style.width = Math.max(pct, 0.2) + '%';
    if (d.global_transferred) document.getElementById('bpTransferred').textContent = d.global_transferred;
    if (d.global_total) document.getElementById('bpTotal').textContent = d.global_total;
    // ETA is computed by the smoothed average-speed block below (near end of refresh).

    // Previous sessions bar overlay - disabled (was broken/confusing)
    document.getElementById('prevBar').style.width = '0%';

    // Session note
    const sn = document.getElementById('sessionNote');
    if (!d.session_num || d.global_total_bytes === 0) {
      sn.textContent = 'Waiting for transfer to start...';
    } else if (d.session_num > 1) {
      sn.textContent = `This session: ${d.session_transferred || '--'} / ${d.session_total || '--'} (${d.session_pct || 0}%)`;
    } else {
      sn.textContent = '';
    }

    // Files
    if (d.global_files_done !== undefined) {
      document.getElementById('filesDone').textContent = d.global_files_done.toLocaleString();
      document.getElementById('filesTotal').textContent = d.global_files_total.toLocaleString();
      document.getElementById('filesPct').textContent = d.global_files_pct;
      document.getElementById('filesBar').style.width = Math.max(d.global_files_pct, 0.2) + '%';
    }

    // Checks
    if (d.checks_done !== undefined) {
      document.getElementById('checksDone').textContent = d.checks_done.toLocaleString();
      document.getElementById('checksTotal').textContent = d.checks_total.toLocaleString();
      const cpct = d.checks_total ? (d.checks_done / d.checks_total * 100) : 0;
      document.getElementById('checksBar').style.width = Math.max(cpct, 0.2) + '%';
    }

    // Speed display
    const speedMbs = parseSpeed(d.speed || '');
    if (d.speed && !d.finished) {
      document.getElementById('speed').style.fontSize = '';
      document.getElementById('speed').textContent = fmtSpeed(speedMbs);
      const realSpeeds = speedHistory.filter(v => v !== null);
      if (realSpeeds.length >= 2) {
        const prev = realSpeeds[realSpeeds.length - 2];
        const diff = speedMbs - prev;
        const arrow = diff > 0.05 ? '\u2191' : diff < -0.05 ? '\u2193' : '\u2192';
        const diffColor = diff > 0 ? 'var(--green)' : diff < 0 ? 'var(--red)' : 'var(--text-secondary)';
        document.getElementById('speedSub').innerHTML = `<span style="color:${diffColor}">${arrow} ${Math.abs(diff).toFixed(2)} MiB/s</span>`;
      }
      if (speedMbs > peakSpeedVal) {
        peakSpeedVal = speedMbs;
        peakSpeedTime = new Date().toLocaleTimeString();
      }
    } else if (d.finished) {
      document.getElementById('speed').textContent = 'paused';
      document.getElementById('speed').style.fontSize = '1rem';
      document.getElementById('speedSub').textContent = 'rclone not running';
    }

    // Avg speed
    if (d.global_transferred_bytes > 0 && d.global_elapsed_sec > 0) {
      const avgMbs = (d.global_transferred_bytes / 1024 / 1024) / d.global_elapsed_sec;
      document.getElementById('avgSpeed').textContent = fmtSpeed(avgMbs);
      document.getElementById('avgSpeedSub').textContent = `across ${d.sessions ? d.sessions.length : (d.session_num || 1)} session(s)`;
    }

    // Peak
    document.getElementById('peakSpeed').textContent = fmtSpeed(peakSpeedVal);
    document.getElementById('peakTime').textContent = peakSpeedTime ? 'at ' + peakSpeedTime : '--';

    // Total active time
    if (d.global_elapsed) {
      document.getElementById('elapsed').textContent = d.global_elapsed;
      document.getElementById('elapsedSub').textContent = `this session: ${d.session_elapsed || '--'}`;
    }

    // Files/min
    if (d.global_files_done && d.global_elapsed_sec > 0) {
      const rate = (d.global_files_done / (d.global_elapsed_sec / 60)).toFixed(1);
      document.getElementById('filesRate').textContent = rate;
      const remaining = (d.global_files_total || 0) - d.global_files_done;
      document.getElementById('filesRateSub').textContent = `~${remaining.toLocaleString()} remaining`;
    }

    // Total copied
    if (d.total_copied_count) {
      document.getElementById('totalCopied').textContent = d.total_copied_count.toLocaleString();
    }

    // Downtime
    let totalDown = 0;
    if (d.downtimes) {
      d.downtimes.forEach(dt => totalDown += dt.duration_sec || 0);
    }
    document.getElementById('downtime').textContent = fmtDuration(totalDown);
    document.getElementById('downtimeSub').textContent = d.downtimes && d.downtimes.length > 0 ? `${d.downtimes.length} pause(s)` : 'no interruptions';

    // Errors
    if (d.errors !== undefined) {
      const el = document.getElementById('errors');
      el.textContent = d.errors;
      el.style.color = d.errors > 0 ? 'var(--red)' : 'var(--green)';
      document.getElementById('errorSub').textContent = d.errors > 0 ? 'retrying may help' : 'none';
    }
    if (d.error_messages && d.error_messages.length > 0) {
      document.getElementById('errorSection').classList.add('show');
      document.getElementById('errorList').innerHTML = d.error_messages.map(e => {
        const friendly = friendlyError(e);
        const isAuth = /token|oauth|expired/i.test(e);
        return `<div class="error-item">${esc(friendly)}${isAuth ? ' <a href="/wizard" style="color:var(--orange);text-decoration:underline;font-size:0.7rem;">Reconnect</a>' : ''}</div>`;
      }).join('');
    } else {
      document.getElementById('errorSection').classList.remove('show');
    }

    // Session timeline - show only last 5 by default
    if (d.sessions && d.sessions.length > 0) {
      const ts = document.getElementById('timelineSection');
      ts.style.display = 'block';
      const totalSessions = d.sessions.length;
      const showAll = window._showAllSessions || false;
      const visibleStart = showAll ? 0 : Math.max(0, totalSessions - 5);
      let html = '';
      if (totalSessions > 5 && !showAll) {
        html += `<div style="text-align:center;margin-bottom:12px;">
          <button onclick="window._showAllSessions=true;refresh();" style="background:var(--bg-card);border:1px solid var(--border);color:var(--text-primary);padding:6px 16px;border-radius:8px;cursor:pointer;font-size:0.75rem;">Show all ${totalSessions} sessions</button>
        </div>`;
      } else if (totalSessions > 5 && showAll) {
        html += `<div style="text-align:center;margin-bottom:12px;">
          <button onclick="window._showAllSessions=false;refresh();" style="background:var(--bg-card);border:1px solid var(--border);color:var(--text-primary);padding:6px 16px;border-radius:8px;cursor:pointer;font-size:0.75rem;">Show last 5 sessions</button>
        </div>`;
      }
      d.sessions.forEach((s, idx) => {
        if (idx < visibleStart) return;
        const isLast = idx === d.sessions.length - 1;
        const dotClass = isLast ? (d.finished ? 'done' : 'active') : 'done';
        const label = isLast && !d.finished ? 'Current Session' : `Session ${s.num}`;
        html += `<div class="tl-item">
          <div class="tl-dot ${dotClass}"></div>
          <div class="tl-header">
            <div class="tl-title">${label}</div>
            <div class="tl-time">${esc(s.start || '--')} \u2192 ${isLast && !d.finished ? 'now' : esc(s.end || '--')}</div>
          </div>
          <div class="tl-stats">
            Transferred: <span>${esc(s.transferred)}</span> \u00b7
            Files: <span>${s.files.toLocaleString()}</span> \u00b7
            Duration: <span>${esc(s.elapsed)}</span>
          </div>
        </div>`;

        if (d.downtimes) {
          const dt = d.downtimes.find(x => x.after_session === idx + 1);
          if (dt) {
            html += `<div class="tl-pause">
              <div class="tl-dot pause" style="left:-20px"></div>
              <div class="tl-pause-inner">Paused for ${esc(dt.duration)}</div>
            </div>`;
          }
        }
      });
      document.getElementById('timeline').innerHTML = html;
    }

    // Charts
    drawAreaChart('speedChart', speedHistory, '#22c55e', 'speedGrad', v => fmtSpeed(v), true);
    drawAreaChart('progressChart', progressHistory, '#3b82f6', 'progGrad', v => v.toFixed(0) + '%', true, 100);
    drawAreaChart('filesChart', filesHistory, '#a78bfa', 'filesGrad', v => Math.round(v).toLocaleString(), true);

    // Active transfers
    const list = document.getElementById('transfersList');
    document.getElementById('transferCount').textContent = (d.active ? d.active.length : 0) + ' active';
    if (d.active && d.active.length) {
      const sorted = [...d.active].sort((a, b) => {
        const aActive = a.pct > 0 && a.speed && a.speed !== '0/s' && a.speed !== '0 B/s';
        const bActive = b.pct > 0 && b.speed && b.speed !== '0/s' && b.speed !== '0 B/s';
        if (aActive && !bActive) return -1;
        if (!aActive && bActive) return 1;
        return b.pct - a.pct;
      });
      list.innerHTML = sorted.map(t => {
        const isStalled = t.pct > 0 && (!t.speed || t.speed === '0/s' || t.speed === '0 B/s');
        const isQueued = t.pct === 0 && (!t.speed || t.speed === '--');
        let eta = t.eta || '';
        if (isStalled || (eta && /^\d{4,}h/.test(eta))) eta = '';
        let statusHtml = esc(t.speed || '--');
        let barColor = 'var(--primary)';
        if (isStalled) {
          statusHtml = '<span style="color:var(--orange);font-size:0.65rem;font-weight:600">STALLED</span>';
          barColor = 'var(--orange)';
        } else if (isQueued) {
          statusHtml = '<span style="color:var(--text-tertiary);font-size:0.65rem;font-weight:600">QUEUED</span>';
          barColor = 'var(--text-tertiary)';
        }
        return `<div class="transfer-item">
          <div class="fname" title="${esc(t.name)}">${esc(t.name)}${t.size ? ' <span style="color:var(--text-secondary);font-size:0.65rem">(' + esc(t.size) + ')</span>' : ''}</div>
          <div class="mini-bar"><div class="mini-fill" style="width:${t.pct}%;background:${barColor}"></div></div>
          <div class="tpct">${t.pct}%</div>
          <div class="tspeed">${statusHtml}</div>
          <div class="teta">${esc(eta)}</div>
        </div>`;
      }).join('');
    } else {
      list.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-secondary);font-size:0.8rem;">No active transfers</div>';
    }

    // Recent files
    if (d.recent_files && d.recent_files.length > 0) {
      document.getElementById('recentFiles').innerHTML = d.recent_files.map(f => {
        const ext = getExtension(f.name);
        return `<div class="recent-file">
          <div class="rf-name" title="${esc(f.name)}">${esc(f.name)}</div>
          <span class="rf-ext" style="background:${getTypeColor(ext)}22;color:${getTypeColor(ext)}">${esc(ext)}</span>
          <div class="rf-time">${f.time}</div>
        </div>`;
      }).join('');
    } else {
      document.getElementById('recentFiles').innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-secondary);font-size:0.8rem;">No recent completions</div>';
    }

    // File types
    const ftData = d.all_file_types || {};
    if (Object.keys(ftData).length > 0) {
      const sorted = Object.entries(ftData).sort((a,b) => b[1]-a[1]);
      const maxC = sorted[0][1];
      document.getElementById('fileTypes').innerHTML = '<div class="types-grid">' +
        sorted.slice(0, 24).map(([ext, count]) => {
          const barW = Math.max(12, (count / maxC) * 80);
          const color = getTypeColor(ext);
          return `<div class="type-badge">
            <div class="type-bar" style="width:${barW}px;background:${color}40;"></div>
            <span class="type-name">.${esc(ext)}</span>
            <span class="type-count">${count}</span>
          </div>`;
        }).join('') + '</div>';
    }

    const lastUpdateEl = document.getElementById('lastUpdate');
    if (lastUpdateEl) lastUpdateEl.textContent = new Date().toLocaleTimeString();

    updateFavicon(pct);

    document.title = (pct > 0 && pct < 100) ? '[' + pct + '%] CloudMirror' : 'CloudMirror';

    // Smoothed ETA based on average speed
    if (pct >= 100) {
        document.getElementById('bpEta').textContent = 'Complete';
        document.getElementById('finishTime').textContent = '';
    } else if (d.global_transferred_bytes > 0 && d.global_total_bytes > 0 && d.global_elapsed_sec > 0) {
        const avgBps = d.global_transferred_bytes / d.global_elapsed_sec;
        const remaining = d.global_total_bytes - d.global_transferred_bytes;
        if (avgBps > 0 && remaining > 0) {
            const etaSec = remaining / avgBps;
            const etaStr = fmtDuration(etaSec);
            document.getElementById('bpEta').textContent = etaStr;
            // Finish time
            const finish = new Date(Date.now() + etaSec * 1000);
            document.getElementById('finishTime').textContent = 'Finish: ' + finish.toLocaleDateString(undefined, {weekday:'short', day:'numeric', month:'short'}) + ', ' + finish.toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});
        }
    }

    // Daily transfer bar chart
    if (d.daily_stats && d.daily_stats.length > 0) {
      document.getElementById('dailyChartSection').style.display = '';
      const maxGib = Math.max(...d.daily_stats.map(x => x.gib));
      const container = document.getElementById('dailyBars');
      container.innerHTML = d.daily_stats.map(ds => {
        const h = maxGib > 0 ? Math.max(4, (ds.gib / maxGib) * 100) : 4;
        const dayLabel = ds.day.slice(5);
        const isToday = ds.day === new Date().toISOString().slice(0,10).replace(/\//g,'-');
        const color = isToday ? 'var(--green)' : 'var(--primary)';
        return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <span style="font-size:0.65rem;color:var(--text-primary)">${esc(ds.gib + ' GiB')}</span>
          <div style="width:100%;height:${h}px;background:${color};border-radius:4px 4px 0 0;opacity:0.7;"></div>
          <span style="font-size:0.6rem;color:var(--text-secondary)">${esc(dayLabel)}</span>
        </div>`;
      }).join('');
    }

    if (d.listed) document.getElementById('footerInfo').textContent = `Listed: ${d.listed.toLocaleString()} objects`;

    checkNotifications(d);

  } catch(e) {
    console.error('Refresh error:', e);
    failCount++;
    if (failCount >= 3) { document.getElementById('connLost').style.display = 'block'; document.body.style.paddingTop = '48px'; document.querySelector('.header').style.top = '48px'; }
  }
}

// Pause / Resume
function showToast(msg, color) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderColor = color || 'var(--primary)';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

async function cancelTransfer() {
  if (!await showConfirmModal('Stop the transfer and start a new one?')) return;
  try {
    const res = await fetch('/api/pause', {method:'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}});
    if (res.ok) {
      window.location.href = '/wizard';
    } else {
      showToast('Failed to cancel transfer.', 'var(--red)');
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'var(--red)');
  }
}

async function doAction(action) {
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
  const btn = document.getElementById(action === 'pause' ? 'btnPause' : 'btnResume');
  const origText = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>${action === 'pause' ? 'Stopping...' : 'Starting...'}`;
  try {
    const res = await fetch(`/api/${action}`, { method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()} });
    const d = await res.json();
    if (d.ok) {
      showToast(d.msg, action === 'pause' ? 'var(--orange)' : 'var(--green)');
      setTimeout(refresh, 2000);
    } else {
      showToast(d.msg, 'var(--red)');
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'var(--red)');
  }
  btn.disabled = false;
  btn.textContent = origText;
}

function updateButtons(isRunning) {
  const btnPause = document.getElementById('btnPause');
  const btnResume = document.getElementById('btnResume');
  const btnPause2 = document.getElementById('btnPause2');
  const btnResume2 = document.getElementById('btnResume2');
  if (isRunning) {
    btnPause.style.display = '';
    btnResume.style.display = 'none';
    if (btnPause2) btnPause2.style.display = '';
    if (btnResume2) btnResume2.style.display = 'none';
  } else {
    btnPause.style.display = 'none';
    btnResume.style.display = '';
    if (btnPause2) btnPause2.style.display = 'none';
    if (btnResume2) btnResume2.style.display = '';
  }
}

// Favicon with progress
// Theme toggle (dark/light)
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  html.setAttribute('data-theme', next);
  localStorage.setItem('cloudmirror-theme', next);
  document.getElementById('theme-icon-dark').style.display = next === 'light' ? 'none' : 'block';
  document.getElementById('theme-icon-light').style.display = next === 'light' ? 'block' : 'none';
  // Clear chart cache so they redraw with new theme colors
  if (drawAreaChart._cache) drawAreaChart._cache = {};
  // Redraw charts with new colors
  drawAreaChart('speedChart', speedHistory, '#22c55e', 'speedGrad', v => fmtSpeed(v), true);
  drawAreaChart('progressChart', progressHistory, '#3b82f6', 'progGrad', v => v.toFixed(0) + '%', true, 100);
  drawAreaChart('filesChart', filesHistory, '#a78bfa', 'filesGrad', v => Math.round(v).toLocaleString(), true);
}
// Load saved theme
(function() {
  const saved = localStorage.getItem('cloudmirror-theme');
  if (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.setAttribute('data-theme', 'light');
    document.getElementById('theme-icon-dark').style.display = 'none';
    document.getElementById('theme-icon-light').style.display = 'block';
  }
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.getElementById('theme-icon-dark').style.display = 'none';
    document.getElementById('theme-icon-light').style.display = 'block';
  }
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem('cloudmirror-theme')) {
      document.documentElement.setAttribute('data-theme', e.matches ? 'light' : 'dark');
      document.getElementById('theme-icon-dark').style.display = e.matches ? 'none' : 'block';
      document.getElementById('theme-icon-light').style.display = e.matches ? 'block' : 'none';
      if (drawAreaChart._cache) drawAreaChart._cache = {};
    }
  });
})();

let _faviconCanvas = null;
let _lastFaviconPct = -1;
function updateFavicon(pct) {
  pct = Math.round(pct);
  if (pct === _lastFaviconPct) return;
  _lastFaviconPct = pct;
  if (!_faviconCanvas) { _faviconCanvas = document.createElement('canvas'); _faviconCanvas.width = 32; _faviconCanvas.height = 32; }
  const canvas = _faviconCanvas;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#0d1220';
  ctx.beginPath(); ctx.arc(16, 16, 16, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = '#6366f1';
  ctx.lineWidth = 4;
  ctx.beginPath();
  ctx.arc(16, 16, 12, -Math.PI/2, -Math.PI/2 + (pct/100) * Math.PI * 2);
  ctx.stroke();
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 11px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(Math.round(pct), 16, 17);
  let link = document.querySelector('link[rel="icon"]');
  if (!link) { link = document.createElement('link'); link.rel = 'icon'; document.head.appendChild(link); }
  link.href = canvas.toDataURL();
}

// Timeline collapse/expand
let tlCollapsed = false;
function toggleTimeline() {
  tlCollapsed = !tlCollapsed;
  document.getElementById('timeline').style.display = tlCollapsed ? 'none' : '';
  document.getElementById('tlToggle').innerHTML = tlCollapsed ? '&#9654;' : '&#9660;';
}

// Sound notification when transfer completes or errors appear
let prevPct = 0;
let prevErrors = -1;
function checkNotifications(d) {
  const pct = d.global_pct || 0;
  if (pct >= 100 && prevPct < 100 && prevPct > 0) {
    playNotifSound(800, 0.3);
    setTimeout(() => playNotifSound(1000, 0.3), 200);
    setTimeout(() => playNotifSound(1200, 0.3), 400);
    if (Notification.permission === 'granted') {
      new Notification('CloudMirror - Transfer Complete!', { body: 'All files have been transferred.' });
    }
  }
  const errs = d.errors || 0;
  if (errs > prevErrors && prevErrors >= 0) {
    playNotifSound(400, 0.2);
    setTimeout(() => playNotifSound(300, 0.2), 150);
  }
  prevPct = pct;
  prevErrors = errs;
}
let _audioCtx = null;
function getAudioCtx() {
  if (!_audioCtx) _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  return _audioCtx;
}
function playNotifSound(freq, dur) {
  try {
    const ctx = getAudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.value = freq;
    gain.gain.value = 0.08;
    osc.start();
    osc.stop(ctx.currentTime + dur);
  } catch(e) {}
}

async function showHistory() {
  try {
    const existing = document.querySelector('[data-history-modal]');
    if (existing) existing.remove();
    const res = await fetch('/api/history');
    const data = await res.json();
    if (!data.length) { showToast('No transfer history found.', 'var(--text-secondary)'); return; }
    let html = '<div data-history-modal style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:300;display:flex;align-items:center;justify-content:center;" onclick="if(event.target===this)this.remove()">';
    html += '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:16px;padding:24px;max-width:600px;width:90%;max-height:80vh;overflow-y:auto;">';
    html += '<h3 style="font-size:1rem;font-weight:700;color:var(--text-primary);margin-bottom:16px;">Transfer History</h3>';
    data.forEach(h => {
      html += '<div style="padding:10px 0;border-bottom:1px solid var(--border);">';
      html += '<div style="font-weight:600;color:var(--text-primary);font-size:0.85rem;">' + esc(h.label) + '</div>';
      html += '<div style="font-size:0.7rem;color:var(--text-secondary);">' + h.sessions + ' session(s)</div>';
      html += '</div>';
    });
    html += '<button onclick="this.parentElement.parentElement.remove()" style="margin-top:16px;padding:10px 24px;border-radius:8px;border:1px solid var(--border);background:var(--bg-card);color:var(--text-primary);cursor:pointer;font-size:0.85rem;">Close</button>';
    html += '</div></div>';
    document.body.insertAdjacentHTML('beforeend', html);
    const histModal = document.querySelector('[data-history-modal]');
    function histEsc(e) { if (e.key === 'Escape' && histModal) { histModal.remove(); document.removeEventListener('keydown', histEsc); } }
    document.addEventListener('keydown', histEsc);
  } catch(e) { showToast('Could not load history.', 'var(--red)'); }
}

refresh();
let refreshInterval = setInterval(refresh, 5000);
window.addEventListener('resize', () => {
  if (drawAreaChart._cache) drawAreaChart._cache = {};
  drawAreaChart('speedChart', speedHistory, '#22c55e', 'speedGrad', v => fmtSpeed(v), true);
  drawAreaChart('progressChart', progressHistory, '#3b82f6', 'progGrad', v => v.toFixed(0) + '%', true, 100);
  drawAreaChart('filesChart', filesHistory, '#a78bfa', 'filesGrad', v => Math.round(v).toLocaleString(), true);
});
</script>
</body>
</html>
"""


# ─── Wizard HTML ──────────────────────────────────────────────────────────────

WIZARD_HTML = r'''<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudMirror Setup</title>
<script>(function(){var t=localStorage.getItem('cloudmirror-theme');if(t)document.documentElement.setAttribute('data-theme',t);})()</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;0,9..40,800;1,9..40,400&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  *:focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }
  html { scrollbar-width: none; }
  :root {
    --bg: #0c0c0f; --card: #16161a; --card-border: rgba(255,255,255,0.05);
    --text: #ececf1; --text-dim: #a1a1aa; --text-muted: #71717a;
    --blue: #6366f1; --blue-light: #818cf8; --green: #34d399;
    --orange: #fb923c; --red: #f87171; --purple: #a78bfa;
    --cyan: #22d3ee; --pink: #f472b6; --card-hover: #1c1c22;
    --surface-2: #1c1c22; --border-hover: rgba(255,255,255,0.1);
    --noise-opacity: 0.03;
  }
  [data-theme="light"] {
    --bg: #f3f4f8; --card: #ffffff; --card-border: rgba(0,0,0,0.06);
    --text: #1a1c2b; --text-dim: #6b6f85; --text-muted: #9b9fb3;
    --blue: #6366f1; --blue-light: #818cf8; --green: #16a34a;
    --orange: #d97706; --red: #dc2626; --purple: #7c3aed;
    --cyan: #0891b2; --pink: #db2777; --card-hover: #f8f8fb;
    --surface-2: #eaebf0; --border-hover: rgba(0,0,0,0.12);
    --noise-opacity: 0.015;
  }
  [data-theme="light"] .wizard-title { color: #1a1c2b; }
  [data-theme="light"] .provider-card:hover { border-color: var(--blue); background: #f0f0ff; }
  [data-theme="light"] .provider-card.selected { background: #eef0ff; }

  html, body { overflow-x: hidden; }
  body::-webkit-scrollbar { width: 0; background: transparent; }
  body {
    font-family: 'DM Sans', -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 20px;
    -webkit-font-smoothing: antialiased;
  }
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    opacity: var(--noise-opacity);
    pointer-events: none;
    z-index: 9999;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
    background-size: 200px;
  }

  .wizard-container {
    max-width: 700px; width: 100%; position: relative;
  }

  /* Theme toggle */
  .theme-toggle {
    position: fixed; top: 20px; right: 20px;
    background: var(--card); border: 1px solid var(--card-border); border-radius: 10px;
    padding: 6px 10px; cursor: pointer; font-size: 1rem; line-height: 1;
    color: var(--text); transition: all 0.2s; z-index: 100;
    min-width: 44px; min-height: 44px;
    display: flex; align-items: center; justify-content: center;
  }
  .theme-toggle:hover { border-color: var(--blue); }

  /* Progress dots */
  .progress-dots {
    display: flex; justify-content: center; gap: 10px; margin-bottom: 32px;
  }
  .dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--card-border); transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .dot.active { background: var(--blue); transform: scale(1.3); box-shadow: 0 0 8px rgba(99,102,241,0.4); }
  .dot.done { background: var(--green); transform: scale(1.1); }

  /* Step containers */
  .step {
    display: none; animation: fadeIn 0.4s ease;
  }
  .step.active { display: block; }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(16px); }
    to { opacity: 1; transform: translateY(0); }
  }

  /* Common elements */
  .wizard-title {
    font-size: 2rem; font-weight: 800; color: #fff;
    text-align: center; margin-bottom: 8px; letter-spacing: -0.03em;
  }
  .wizard-subtitle {
    font-size: 1rem; color: var(--text-dim);
    text-align: center; margin-bottom: 32px; line-height: 1.6;
  }
  .wizard-card {
    background: var(--card); border: 1px solid var(--card-border);
    border-radius: 16px; padding: 32px; margin-bottom: 16px;
  }

  /* Welcome step */
  .welcome-logo {
    font-size: 3.5rem; text-align: center; margin-bottom: 16px;
  }

  /* Provider cards grid */
  .providers-grid {
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;
  }
  @media (max-width: 600px) { .providers-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 400px) {
    .wizard-card { padding: 20px 16px; }
    .wizard-title { font-size: 1.3rem; }
  }


  .advanced-toggle {
    display: flex; align-items: center; gap: 8px; cursor: pointer;
    padding: 12px 0; color: var(--text-dim); font-size: 0.8rem;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
    border-top: 1px solid var(--card-border); margin-top: 16px;
    user-select: none;
  }
  .advanced-toggle:hover { color: var(--text); }
  .advanced-toggle .arrow { transition: transform 0.3s; font-size: 0.6rem; }
  .advanced-toggle .arrow.open { transform: rotate(90deg); }
  .advanced-content { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }
  .advanced-content.open { max-height: 500px; }

  .provider-card {
    background: var(--card); border: 2px solid var(--card-border);
    border-radius: 16px; padding: 20px 16px; text-align: center;
    cursor: pointer; transition: all 0.2s; user-select: none;
  }
  .provider-card:hover { border-color: var(--blue); background: var(--card-hover); transform: translateY(-2px); box-shadow: 0 4px 20px rgba(99,102,241,0.15); }
  .provider-card.selected { border-color: var(--blue); background: rgba(99,102,241,0.08); }
  .provider-card.disabled {
    opacity: 0.35; pointer-events: none; cursor: not-allowed;
    position: relative;
  }
  .provider-card.disabled::after {
    content: 'Already selected as source';
    display: block; font-size: 0.6rem; color: var(--text-muted);
    margin-top: 6px; font-weight: 400;
  }
  .provider-icon { font-size: 2.2rem; margin-bottom: 8px; }
  .provider-name { font-size: 0.85rem; font-weight: 600; color: var(--text); }

  /* Buttons */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 14px 32px; border-radius: 10px; font-size: 1rem; font-weight: 600;
    border: none; cursor: pointer; transition: all 0.2s; font-family: inherit;
  }
  .btn-primary {
    background: linear-gradient(135deg, #4f46e5, var(--blue)); color: #fff;
    box-shadow: 0 4px 14px rgba(99,102,241,0.3);
  }
  .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(99,102,241,0.4); filter: brightness(1.1); }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; transform: none; box-shadow: none; }
  .btn-secondary {
    background: var(--card); color: var(--text-dim); border: 1px solid var(--card-border);
  }
  .btn-secondary:hover { border-color: var(--text-dim); color: var(--text); }
  .btn-big {
    width: 100%; padding: 18px; font-size: 1.1rem; border-radius: 10px;
  }
  .btn-connect {
    padding: 10px 20px; border-radius: 10px; font-size: 0.85rem;
  }
  .btn-row {
    display: flex; justify-content: space-between; align-items: center;
    margin-top: 24px;
  }
  .btn-row.center { justify-content: center; }

  /* Form elements */
  .form-group { margin-bottom: 20px; }
  .form-label {
    display: block; font-size: 0.8rem; font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    color: var(--text-dim); margin-bottom: 8px; text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .form-input {
    width: 100%; padding: 12px 16px; border-radius: 10px;
    background: var(--bg); border: 1px solid var(--card-border);
    color: var(--text); font-size: 1rem; font-family: inherit;
    transition: border-color 0.2s;
  }
  .form-input:focus:not(:focus-visible) { outline: none; }
  .form-input:focus { border-color: var(--blue); }
  .form-input::placeholder { color: var(--text-muted); }
  .form-hint { font-size: 0.75rem; color: var(--text-muted); margin-top: 6px; }

  /* Speed radio cards */
  .speed-options { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  @media (max-width: 500px) { .speed-options { grid-template-columns: 1fr; } }
  .speed-card {
    background: var(--bg); border: 2px solid var(--card-border);
    border-radius: 12px; padding: 14px; text-align: center;
    cursor: pointer; transition: all 0.2s;
  }
  .speed-card:hover { border-color: var(--blue); }
  .speed-card.selected { border-color: var(--blue); background: rgba(99,102,241,0.06); }
  .speed-card input { display: none; }
  .speed-label { font-size: 0.9rem; font-weight: 600; color: var(--text); }
  .speed-desc { font-size: 0.7rem; color: var(--text-dim); margin-top: 4px; }

  /* Connect step */
  .connect-item {
    display: flex; justify-content: space-between; align-items: center;
    background: var(--bg); border: 1px solid var(--card-border);
    border-radius: 12px; padding: 16px 20px; margin-bottom: 10px;
  }
  .connect-info { display: flex; align-items: center; gap: 12px; }
  .connect-icon { font-size: 1.5rem; }
  .connect-name { font-weight: 600; font-size: 0.95rem; }
  .connect-status { font-size: 0.75rem; margin-top: 2px; }
  .connect-status.ok { color: var(--green); }
  .connect-status.pending { color: var(--text-muted); }

  .checkmark {
    width: 28px; height: 28px; border-radius: 50%;
    background: rgba(34,197,94,0.15); border: 2px solid var(--green);
    display: flex; align-items: center; justify-content: center;
    color: var(--green); font-size: 0.9rem; font-weight: 700;
  }

  /* Summary */
  .summary-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 0; border-bottom: 1px solid var(--card-border);
  }
  .summary-row:last-child { border-bottom: none; }
  .summary-label { font-size: 0.85rem; color: var(--text-dim); }
  .summary-value { font-size: 0.95rem; font-weight: 600; color: var(--text); }

  /* Loading spinner */
  .spinner {
    width: 18px; height: 18px; border: 2px solid var(--card-border);
    border-top-color: var(--blue); border-radius: 50%;
    animation: spin 0.6s linear infinite; display: inline-block;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Local path input (shown when Local Folder is selected) */
  .local-path-input {
    margin-top: 12px; display: none;
  }
  .local-path-input.show { display: block; }
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme" aria-label="Toggle dark/light mode">&#9790;</button>

<div class="wizard-container">
  <div class="progress-dots" id="progressDots">
    <div class="dot active"></div>
    <div class="dot"></div>
    <div class="dot"></div>
    <div class="dot"></div>
    <div class="dot"></div>
    <div class="dot"></div>
  </div>

  <!-- Step 1: Welcome -->
  <div class="step active" id="step1">
    <div class="wizard-card" style="text-align:center; padding: 48px 32px;">
      <div class="welcome-logo">
    <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
        <path d="M48 28c0-8.8-7.2-16-16-16-6.5 0-12.1 3.9-14.6 9.5C16.5 21.2 15.8 21 15 21c-3.3 0-6 2.7-6 6 0 .4 0 .8.1 1.1C5.5 29.5 3 33.2 3 37.5 3 43 7.5 47.5 13 47.5h35c4.4 0 8-3.6 8-8s-3.6-8-8-8c-.3 0-.7 0-1 .1.6-1.1 1-2.3 1-3.6z" fill="url(#cloudGrad)"/>
        <path d="M22 36h20M38 31l5 5-5 5" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
        <defs>
            <linearGradient id="cloudGrad" x1="3" y1="20" x2="56" y2="48" gradientUnits="userSpaceOnUse">
                <stop stop-color="#4f46e5"/>
                <stop offset="1" stop-color="#818cf8"/>
            </linearGradient>
        </defs>
    </svg>
</div>
      <div class="wizard-title">CloudMirror</div>
      <div class="wizard-subtitle">
        The easiest way to copy files between cloud storage services.<br>
        No technical knowledge needed.
      </div>
      <button class="btn btn-primary btn-big" onclick="goTo(2)">
        Get Started
      </button>
      <div style="margin-top: 16px; font-size: 0.75rem; color: var(--text-muted);">
        Supports Google Drive, OneDrive, Dropbox, S3, and more
      </div>
      <div id="welcomeRcloneCheck" style="margin-top:12px;font-size:0.75rem;text-align:center;"></div>
    </div>
  </div>

  <!-- Step 2: Source -->
  <div class="step" id="step2">
    <div class="wizard-title" style="font-size:1.5rem;">Where are your files?</div>
    <div class="wizard-subtitle">Select the cloud storage where your files currently live.</div>
    <div class="providers-grid" id="sourceGrid">
      <div class="provider-card" data-provider="drive" data-name="Google Drive" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><div style="font-size:2.2rem;font-weight:800;line-height:1;"><span style="color:#4285f4">G</span><span style="color:#ea4335">o</span><span style="color:#fbbc05">o</span><span style="color:#4285f4">g</span><span style="color:#34a853">l</span><span style="color:#ea4335">e</span></div><div style="font-size:0.7rem;color:var(--text-dim);margin-top:2px;">Drive</div></div>
        <div class="provider-name">Google Drive</div>
      </div>
      <div class="provider-card" data-provider="onedrive" data-name="OneDrive" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="48" height="32" viewBox="0 0 48 32"><path d="M39.5 16C39.5 9.1 33.9 3.5 27 3.5c-5.1 0-9.5 3-11.5 7.4C14.8 10.3 14 10 13 10c-2.8 0-5 2.2-5 5 0 .3 0 .6.1.9C4.6 17 2 20.1 2 23.5 2 27.6 5.4 31 9.5 31h28c3.6 0 6.5-2.9 6.5-6.5S43.1 18 39.5 16z" fill="#0078d4"/></svg></div>
        <div class="provider-name">OneDrive</div>
      </div>
      <div class="provider-card" data-provider="dropbox" data-name="Dropbox" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M12 2L2 8.5l10 6.5 10-6.5L12 2zm16 0L18 8.5l10 6.5 10-6.5L28 2zM2 21.5L12 28l10-6.5-10-6.5L2 21.5zm26-6.5l-10 6.5 10 6.5 10-6.5-10-6.5zM12 29.5l10 6.5 10-6.5-10-6.5-10 6.5z" fill="#0061fe"/></svg></div>
        <div class="provider-name">Dropbox</div>
      </div>
      <div class="provider-card" data-provider="mega" data-name="MEGA" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M8 30V10l8 12 8-12v20h-4V18l-4 6-4-6v12H8z" fill="#d9272e"/></svg></div>
        <div class="provider-name">MEGA</div>
      </div>
      <div class="provider-card" data-provider="s3" data-name="Amazon S3" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M20 4c-6.6 0-12 2.7-12 6v20c0 3.3 5.4 6 12 6s12-2.7 12-6V10c0-3.3-5.4-6-12-6z" fill="none" stroke="#ff9900" stroke-width="2.5"/><ellipse cx="20" cy="10" rx="12" ry="6" fill="none" stroke="#ff9900" stroke-width="2.5"/><path d="M8 20c0 3.3 5.4 6 12 6s12-2.7 12-6" fill="none" stroke="#ff9900" stroke-width="2"/></svg></div>
        <div class="provider-name">Amazon S3</div>
      </div>
      <div class="provider-card" data-provider="protondrive" data-name="Proton Drive" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M20 3L6 10v10c0 9.5 5.9 18.4 14 20 8.1-1.6 14-10.5 14-20V10L20 3z" fill="#6d4aff"/></svg></div>
        <div class="provider-name">Proton Drive</div>
      </div>
      <div class="provider-card" data-provider="local" data-name="Local Folder" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M6 10c0-1.1.9-2 2-2h8l3 3h13c1.1 0 2 .9 2 2v17c0 1.1-.9 2-2 2H8c-1.1 0-2-.9-2-2V10z" fill="#60a5fa"/><path d="M6 15h28v15c0 1.1-.9 2-2 2H8c-1.1 0-2-.9-2-2V15z" fill="#3b82f6"/></svg></div>
        <div class="provider-name">Local Folder</div>
      </div>
      <div class="provider-card" data-provider="other" data-name="Other" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="20">&#x2699;&#xFE0F;</text></svg></div>
        <div class="provider-name">Other</div>
      </div>
    </div>
    <div class="local-path-input" id="sourceLocalPath">
      <div class="form-group" style="margin-top:16px;">
        <label class="form-label" for="sourcePathInput">Folder Path</label>
        <input class="form-input" id="sourcePathInput" type="text" placeholder="e.g. /Users/you/Documents">
        <div id="sourcePathError" style="display:none;font-size:0.75rem;color:var(--red);margin-top:6px;"></div>
        <div class="form-hint">The folder on your computer where your files are stored.</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;">
          <button type="button" class="btn-secondary" style="padding:10px 14px;font-size:0.75rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);min-height:44px;" onclick="document.getElementById('sourcePathInput').value=((window._homeDir||'/tmp')+'/Desktop');document.getElementById('sourcePathInput').dispatchEvent(new Event('input'))">Desktop</button>
          <button type="button" class="btn-secondary" style="padding:10px 14px;font-size:0.75rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);min-height:44px;" onclick="document.getElementById('sourcePathInput').value=((window._homeDir||'/tmp')+'/Documents');document.getElementById('sourcePathInput').dispatchEvent(new Event('input'))">Documents</button>
          <button type="button" class="btn-secondary" style="padding:10px 14px;font-size:0.75rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);min-height:44px;" onclick="document.getElementById('sourcePathInput').value=((window._homeDir||'/tmp')+'/Downloads');document.getElementById('sourcePathInput').dispatchEvent(new Event('input'))">Downloads</button>
        </div>
      </div>
    </div>
    <div class="local-path-input" id="sourceOtherName">
      <div class="form-group" style="margin-top:16px;">
        <label class="form-label" for="sourceOtherInput">Remote Name</label>
        <input class="form-input" id="sourceOtherInput" type="text" placeholder="myremote">
        <div class="form-hint">For cloud services not listed above. Enter the name you set up using rclone (e.g. "backblaze", "wasabi", "pcloud").</div>
      </div>
    </div>
    <div class="btn-row">
      <button class="btn btn-secondary" onclick="goTo(1)">Back</button>
      <button class="btn btn-primary" id="sourceNext" onclick="goTo(3)" disabled>Next</button>
    </div>
  </div>

  <!-- Step 3: Destination -->
  <div class="step" id="step3">
    <div class="wizard-title" style="font-size:1.5rem;">Where do you want to copy them?</div>
    <div class="wizard-subtitle">Select the destination cloud storage.</div>
    <div class="providers-grid" id="destGrid">
      <div class="provider-card" data-provider="drive" data-name="Google Drive" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><div style="font-size:2.2rem;font-weight:800;line-height:1;"><span style="color:#4285f4">G</span><span style="color:#ea4335">o</span><span style="color:#fbbc05">o</span><span style="color:#4285f4">g</span><span style="color:#34a853">l</span><span style="color:#ea4335">e</span></div><div style="font-size:0.7rem;color:var(--text-dim);margin-top:2px;">Drive</div></div>
        <div class="provider-name">Google Drive</div>
      </div>
      <div class="provider-card" data-provider="onedrive" data-name="OneDrive" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><svg width="48" height="32" viewBox="0 0 48 32"><path d="M39.5 16C39.5 9.1 33.9 3.5 27 3.5c-5.1 0-9.5 3-11.5 7.4C14.8 10.3 14 10 13 10c-2.8 0-5 2.2-5 5 0 .3 0 .6.1.9C4.6 17 2 20.1 2 23.5 2 27.6 5.4 31 9.5 31h28c3.6 0 6.5-2.9 6.5-6.5S43.1 18 39.5 16z" fill="#0078d4"/></svg></div>
        <div class="provider-name">OneDrive</div>
      </div>
      <div class="provider-card" data-provider="dropbox" data-name="Dropbox" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M12 2L2 8.5l10 6.5 10-6.5L12 2zm16 0L18 8.5l10 6.5 10-6.5L28 2zM2 21.5L12 28l10-6.5-10-6.5L2 21.5zm26-6.5l-10 6.5 10 6.5 10-6.5-10-6.5zM12 29.5l10 6.5 10-6.5-10-6.5-10 6.5z" fill="#0061fe"/></svg></div>
        <div class="provider-name">Dropbox</div>
      </div>
      <div class="provider-card" data-provider="mega" data-name="MEGA" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="16" font-weight="800" fill="#d9272e">MEGA</text></svg></div>
        <div class="provider-name">MEGA</div>
      </div>
      <div class="provider-card" data-provider="s3" data-name="Amazon S3" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="24" font-weight="800" fill="#ff9900">S3</text></svg></div>
        <div class="provider-name">Amazon S3</div>
      </div>
      <div class="provider-card" data-provider="protondrive" data-name="Proton Drive" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M20 3L6 10v10c0 9.5 5.9 18.4 14 20 8.1-1.6 14-10.5 14-20V10L20 3z" fill="#6d4aff"/></svg></div>
        <div class="provider-name">Proton Drive</div>
      </div>
      <div class="provider-card" data-provider="local" data-name="Local Folder" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="24">&#x1F4BB;</text></svg></div>
        <div class="provider-name">Local Folder</div>
      </div>
      <div class="provider-card" data-provider="other" data-name="Other" tabindex="0" role="button" onclick="selectDest(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectDest(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="20">&#x2699;&#xFE0F;</text></svg></div>
        <div class="provider-name">Other</div>
      </div>
    </div>
    <div class="local-path-input" id="destLocalPath">
      <div class="form-group" style="margin-top:16px;">
        <label class="form-label" for="destPathInput">Save to Folder</label>
        <input class="form-input" id="destPathInput" type="text" placeholder="e.g. /Users/you/Desktop/Backup">
        <div id="destPathError" style="display:none;font-size:0.75rem;color:var(--red);margin-top:6px;"></div>
        <div class="form-hint">Where to save the copied files on your computer.</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;">
          <button type="button" style="padding:10px 14px;font-size:0.75rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);min-height:44px;" onclick="document.getElementById('destPathInput').value=((window._homeDir||'/tmp')+'/Desktop/CloudMirror-Backup');document.getElementById('destPathInput').dispatchEvent(new Event('input'))">Desktop/CloudMirror-Backup</button>
          <button type="button" style="padding:10px 14px;font-size:0.75rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);min-height:44px;" onclick="document.getElementById('destPathInput').value=((window._homeDir||'/tmp')+'/Documents/CloudMirror-Backup');document.getElementById('destPathInput').dispatchEvent(new Event('input'))">Documents/CloudMirror-Backup</button>
        </div>
      </div>
    </div>
    <div class="local-path-input" id="destOtherName">
      <div class="form-group" style="margin-top:16px;">
        <label class="form-label" for="destOtherInput">Remote Name</label>
        <input class="form-input" id="destOtherInput" type="text" placeholder="myremote">
        <div class="form-hint">For cloud services not listed above. Enter the name you set up using rclone (e.g. "backblaze", "wasabi", "pcloud").</div>
      </div>
    </div>
    <div class="btn-row">
      <button class="btn btn-secondary" onclick="goTo(2)">Back</button>
      <button class="btn btn-primary" id="destNext" onclick="goTo(4)" disabled>Next</button>
    </div>
  </div>

  <!-- Step 4: Options -->
  <div class="step" id="step4">
    <div class="wizard-title" style="font-size:1.5rem;">Transfer Options</div>
    <div class="wizard-subtitle">Fine-tune your transfer. All fields are optional.</div>
    <div class="wizard-card">
      <div class="form-group">
        <label class="form-label" for="sourceSubfolder">Source Subfolder (optional)</label>
        <input class="form-input" id="sourceSubfolder" type="text" placeholder="e.g. Documents/Work">
        <div class="form-hint">Leave empty to copy everything from the root</div>
      </div>
      <div class="form-group">
        <label class="form-label" for="destSubfolder">Destination Subfolder (optional)</label>
        <input class="form-input" id="destSubfolder" type="text" placeholder="e.g. Backup/2024">
        <div class="form-hint">Leave empty to copy to the root</div>
      </div>
      <div class="form-group">
        <label class="form-label">Transfer Speed</label>
        <div class="speed-options" role="radiogroup" aria-label="Transfer speed">
          <div class="speed-card" role="radio" aria-checked="false" onclick="selectSpeed(this, '4')">
            <input type="radio" name="speed" value="4">
            <div class="speed-label">Normal</div>
            <div class="speed-desc">4 files at a time</div>
          </div>
          <div class="speed-card selected" role="radio" aria-checked="true" onclick="selectSpeed(this, '8')">
            <input type="radio" name="speed" value="8" checked>
            <div class="speed-label">Fast</div>
            <div class="speed-desc">8 files at a time</div>
          </div>
          <div class="speed-card" role="radio" aria-checked="false" onclick="selectSpeed(this, '16')">
            <input type="radio" name="speed" value="16">
            <div class="speed-label">Maximum</div>
            <div class="speed-desc">16 files at a time</div>
          </div>
        </div>
      </div>
      <div class="advanced-toggle" onclick="toggleAdvanced()">
    <span class="arrow" id="advArrow">&#9654;</span>
    Advanced Options
</div>
<div class="advanced-content" id="advancedContent">
      <div class="form-group">
        <label class="form-label" for="excludePatterns">Exclude Patterns (optional)</label>
        <input class="form-input" id="excludePatterns" type="text" placeholder="Trash, .Trash, Personal Vault">
        <div class="form-hint">Comma-separated folder names to skip</div>
      </div>
      <div class="form-group" style="margin-bottom:0;">
        <label class="form-label" for="bwLimit">Bandwidth Limit (optional)</label>
        <input class="form-input" id="bwLimit" type="text" placeholder="e.g. 10M, 1G, 500K">
        <div class="form-hint">Limit upload/download speed. Leave empty for unlimited.</div>
      </div>
      <div class="form-group" style="margin-bottom:0;margin-top:20px;">
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;">
          <input type="checkbox" id="useChecksum" style="width:18px;height:18px;">
          <div>
            <div class="form-label" style="margin-bottom:0;">Verify with checksums</div>
            <div class="form-hint">Slower but ensures file integrity. Recommended for important data.</div>
          </div>
        </label>
      </div>
</div>
    </div>
    <div class="btn-row">
      <button class="btn btn-secondary" onclick="goTo(3)">Back</button>
      <button class="btn btn-primary" onclick="goTo(5)">Next</button>
    </div>
  </div>

  <!-- Step 5: Connect -->
  <div class="step" id="step5">
    <div class="wizard-title" style="font-size:1.5rem;">Connect Your Accounts</div>
    <div class="wizard-subtitle">Authorize CloudMirror to access your cloud storage.</div>
    <div class="wizard-card" id="connectList">
      <!-- Filled dynamically -->
    </div>
    <div id="rcloneStatus" style="text-align:center; margin-bottom:16px;"></div>
    <div id="connectHint" style="font-size:0.8rem;color:var(--text-dim);margin-bottom:16px;text-align:center;"></div>
    <div class="btn-row">
      <button class="btn btn-secondary" onclick="goTo(4)">Back</button>
      <button class="btn btn-primary" id="connectNext" onclick="goTo(6)" disabled>Next</button>
    </div>
  </div>

  <!-- Step 6: Ready -->
  <div class="step" id="step6">
    <div class="wizard-title" style="font-size:1.5rem;">Ready to Go!</div>
    <div class="wizard-subtitle">Review your transfer and start copying.</div>
    <div class="wizard-card" id="summaryCard">
      <!-- Filled dynamically -->
    </div>
    <div class="btn-row" style="flex-direction:column; gap:12px;">
      <div style="text-align:center;padding:12px 16px;margin-bottom:16px;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);border-radius:10px;font-size:0.8rem;color:var(--green);">
        This will <strong>copy</strong> your files. Your originals will stay untouched.
      </div>
      <button class="btn btn-secondary btn-big" id="previewBtn" onclick="previewTransfer()" style="margin-bottom:12px;">
        Preview (see what will be copied)
      </button>
      <div id="previewResult" style="display:none;margin-bottom:16px;padding:16px;background:var(--bg);border:1px solid var(--card-border);border-radius:12px;font-size:0.85rem;color:var(--text);"></div>
      <div id="wizardError" style="display:none;padding:12px 16px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:10px;font-size:0.85rem;color:var(--red);text-align:center;margin-bottom:12px;"></div>
      <button class="btn btn-primary btn-big" id="startBtn" onclick="startTransfer()">
        Start Transfer
      </button>
      <button class="btn btn-secondary" onclick="goTo(5)" style="align-self:flex-start;">Back</button>
    </div>
  </div>
</div>

<script>
function getCsrfToken(){return document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith('csrf_token='))?.substring('csrf_token='.length)||''}
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
// State
let currentStep = 1;
let sourceProvider = null;
let sourceName = '';
let sourceDisplayName = '';
let destProvider = null;
let destName = '';
let destDisplayName = '';
let selectedSpeed = '8';
let existingRemotes = [];

const providerKeys = {
  drive: 'gdrive', onedrive: 'onedrive', dropbox: 'dropbox', mega: 'mega', s3: 's3', protondrive: 'protondrive', local: 'local', other: null
};
const providerIcons = {
  drive: '<div style="font-size:1.5rem;font-weight:800;line-height:1;"><span style="color:#4285f4">G</span><span style="color:#ea4335">o</span><span style="color:#fbbc05">o</span><span style="color:#4285f4">g</span><span style="color:#34a853">l</span><span style="color:#ea4335">e</span></div>',
  onedrive: '<svg width="32" height="22" viewBox="0 0 48 32"><path d="M39.5 16C39.5 9.1 33.9 3.5 27 3.5c-5.1 0-9.5 3-11.5 7.4C14.8 10.3 14 10 13 10c-2.8 0-5 2.2-5 5 0 .3 0 .6.1.9C4.6 17 2 20.1 2 23.5 2 27.6 5.4 31 9.5 31h28c3.6 0 6.5-2.9 6.5-6.5S43.1 18 39.5 16z" fill="#0078d4"/></svg>',
  dropbox: '<svg width="28" height="28" viewBox="0 0 40 40"><path d="M12 2L2 8.5l10 6.5 10-6.5L12 2zm16 0L18 8.5l10 6.5 10-6.5L28 2zM2 21.5L12 28l10-6.5-10-6.5L2 21.5zm26-6.5l-10 6.5 10 6.5 10-6.5-10-6.5zM12 29.5l10 6.5 10-6.5-10-6.5-10 6.5z" fill="#0061fe"/></svg>',
  mega: '<svg width="28" height="28" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="16" font-weight="800" fill="#d9272e">MEGA</text></svg>',
  s3: '<svg width="28" height="28" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="24" font-weight="800" fill="#ff9900">S3</text></svg>',
  protondrive: '<svg width="28" height="28" viewBox="0 0 40 40"><path d="M20 3L6 10v10c0 9.5 5.9 18.4 14 20 8.1-1.6 14-10.5 14-20V10L20 3z" fill="#6d4aff"/></svg>',
  local: '<svg width="28" height="28" viewBox="0 0 24 24"><path d="M20 6h-8l-2-2H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z" fill="var(--text-dim)"/></svg>',
  other: '<svg width="28" height="28" viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1112 8.4a3.6 3.6 0 010 7.2z" fill="var(--text-dim)"/></svg>'
};

// Theme
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  html.setAttribute('data-theme', next);
  document.querySelector('.theme-toggle').textContent = next === 'light' ? '\u2600' : '\u263E';
  localStorage.setItem('cloudmirror-theme', next);
}
(function() {
  const saved = localStorage.getItem('cloudmirror-theme');
  if (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('.theme-toggle').textContent = '\u2600';
  }
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('.theme-toggle').textContent = '\u2600';
  }
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem('cloudmirror-theme')) {
      document.documentElement.setAttribute('data-theme', e.matches ? 'light' : 'dark');
      document.querySelector('.theme-toggle').textContent = e.matches ? '\u2600' : '\u263E';
    }
  });
})();

// Fetch home directory and check rclone on page load
(function() {
  fetch('/api/wizard/status').then(r => r.json()).then(d => {
    if (d.home_dir) window._homeDir = d.home_dir;
    const el = document.getElementById('welcomeRcloneCheck');
    if (!d.rclone_installed) {
      el.innerHTML = '<span style="color:var(--orange)">rclone is not installed. It will be installed automatically when you proceed.</span>';
    }
  }).catch(() => {});
})();

// Styled confirm modal (replaces native confirm())
function showConfirmModal(message) {
  return new Promise((resolve) => {
    if (document.getElementById('_cm_wiz_overlay')) return resolve(false);
    const overlay = document.createElement('div');
    overlay.id = '_cm_wiz_overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:400;display:flex;align-items:center;justify-content:center;';
    const box = document.createElement('div');
    box.style.cssText = 'background:var(--card);border:1px solid var(--card-border);border-radius:16px;padding:28px 24px;max-width:440px;width:90%;text-align:center;';
    box.innerHTML = '<div style="font-size:0.95rem;color:var(--text);margin-bottom:20px;line-height:1.6;">' + message.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</div>'
      + '<div style="display:flex;gap:12px;justify-content:center;">'
      + '<button id="cmConfirmCancel" class="btn btn-secondary" style="padding:10px 24px;border-radius:10px;font-size:0.85rem;cursor:pointer;">Cancel</button>'
      + '<button id="cmConfirmOk" class="btn btn-primary" style="padding:10px 24px;border-radius:10px;font-size:0.85rem;cursor:pointer;">Continue</button>'
      + '</div>';
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    function cleanup() { overlay.remove(); document.removeEventListener('keydown', escHandler); }
    function escHandler(e) { if (e.key === 'Escape') { cleanup(); resolve(false); } }
    document.addEventListener('keydown', escHandler);
    box.querySelector('#cmConfirmCancel').onclick = () => { cleanup(); resolve(false); };
    box.querySelector('#cmConfirmOk').onclick = () => { cleanup(); resolve(true); };
    overlay.addEventListener('click', (e) => { if (e.target === overlay) { cleanup(); resolve(false); } });
    box.querySelector('#cmConfirmOk').focus();
  });
}

// Navigation
async function goTo(step) {
  if (step >= 3 && !sourceProvider) return;
  if (step >= 4 && !destProvider) return;
  if (step === 3) updateDestGrid();
  if (step === 5) buildConnectStep();
  if (step === 6) {
    if (sourceProvider === destProvider && sourceProvider !== 'local') {
      const proceed = await showConfirmModal('Source and destination are the same service. Two separate accounts will be set up (e.g. &ldquo;gdrive&rdquo; for source and &ldquo;gdrive_dest&rdquo; for destination). Continue?');
      if (!proceed) return;
    }
    buildSummary();
  }

  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  document.getElementById('step' + step).classList.add('active');

  const dots = document.querySelectorAll('.dot');
  dots.forEach((d, i) => {
    d.classList.remove('active', 'done');
    if (i < step - 1) d.classList.add('done');
    if (i === step - 1) d.classList.add('active');
  });
  currentStep = step;
  // Save wizard state to survive page refresh
  try {
    sessionStorage.setItem('cm_wizard', JSON.stringify({
      step: currentStep, sourceProvider, sourceName, sourceDisplayName,
      destProvider, destName, destDisplayName, selectedSpeed
    }));
  } catch(e) {}
}

function toggleAdvanced() {
    const content = document.getElementById('advancedContent');
    const arrow = document.getElementById('advArrow');
    content.classList.toggle('open');
    arrow.classList.toggle('open');
}

// Restore wizard state after refresh
(function() {
  try {
    const saved = sessionStorage.getItem('cm_wizard');
    if (!saved) return;
    const s = JSON.parse(saved);
    if (!s.sourceProvider) return;
    sourceProvider = s.sourceProvider;
    sourceName = s.sourceName || '';
    sourceDisplayName = s.sourceDisplayName || '';
    destProvider = s.destProvider;
    destName = s.destName || '';
    destDisplayName = s.destDisplayName || '';
    selectedSpeed = s.selectedSpeed || '8';
    // Re-select cards visually
    if (sourceProvider) {
      const sc = document.querySelector('#sourceGrid [data-provider="'+sourceProvider+'"]');
      if (sc) sc.classList.add('selected');
    }
    if (destProvider) {
      const dc = document.querySelector('#destGrid [data-provider="'+destProvider+'"]');
      if (dc) dc.classList.add('selected');
    }
    if (s.step > 1) goTo(s.step);
  } catch(e) {}
})();

// Source selection
function selectSource(card) {
  document.querySelectorAll('#sourceGrid .provider-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  sourceProvider = card.dataset.provider;
  sourceDisplayName = card.dataset.name;
  sourceName = providerKeys[sourceProvider] || sourceProvider;

  document.getElementById('sourceLocalPath').classList.toggle('show', sourceProvider === 'local');
  document.getElementById('sourceOtherName').classList.toggle('show', sourceProvider === 'other');
  // For Other provider, only enable Next when name is entered
  if (sourceProvider === 'other') {
    const input = document.getElementById('sourceOtherInput');
    document.getElementById('sourceNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        sourceName = input.value.trim();
        document.getElementById('sourceNext').disabled = !input.value.trim();
      });
    }
  } else if (sourceProvider === 'local') {
    const input = document.getElementById('sourcePathInput');
    document.getElementById('sourceNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        document.getElementById('sourceNext').disabled = !input.value.trim();
      });
    }
  } else {
    document.getElementById('sourceNext').disabled = false;
  }
}

// Dest selection
function selectDest(card) {
  if (card.classList.contains('disabled')) return;
  document.querySelectorAll('#destGrid .provider-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  destProvider = card.dataset.provider;
  destDisplayName = card.dataset.name;
  destName = providerKeys[destProvider] || destProvider;
  if (destProvider === sourceProvider && sourceProvider !== 'local') {
    destName = sourceName + '_dest';
  }

  document.getElementById('destLocalPath').classList.toggle('show', destProvider === 'local');
  document.getElementById('destOtherName').classList.toggle('show', destProvider === 'other');
  // For Other provider, only enable Next when name is entered
  if (destProvider === 'other') {
    const input = document.getElementById('destOtherInput');
    document.getElementById('destNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        destName = input.value.trim();
        document.getElementById('destNext').disabled = !input.value.trim();
      });
    }
  } else if (destProvider === 'local') {
    const input = document.getElementById('destPathInput');
    document.getElementById('destNext').disabled = !input.value.trim();
    if (!input.dataset.listening) {
      input.dataset.listening = 'true';
      input.addEventListener('input', () => {
        document.getElementById('destNext').disabled = !input.value.trim();
      });
    }
  } else {
    document.getElementById('destNext').disabled = false;
  }
}

function updateDestGrid() {
  document.querySelectorAll('#destGrid .provider-card').forEach(c => {
    c.classList.remove('disabled');
    const note = c.querySelector('.same-provider-note');
    if (note) note.remove();
    if (c.dataset.provider === sourceProvider && sourceProvider !== 'local' && sourceProvider !== 'other') {
      const span = document.createElement('div');
      span.className = 'same-provider-note';
      span.style.cssText = 'font-size:0.75rem;color:var(--text-dim);margin-top:4px;';
      span.textContent = '(will configure as separate account)';
      c.appendChild(span);
    }
  });
}

function selectSpeed(card, val) {
  document.querySelectorAll('.speed-card').forEach(c => { c.classList.remove('selected'); c.setAttribute('aria-checked', 'false'); });
  card.classList.add('selected');
  card.setAttribute('aria-checked', 'true');
  selectedSpeed = val;
}

// Build connect step
async function buildConnectStep() {
  const list = document.getElementById('connectList');
  list.innerHTML = '';

  // Set hint based on provider types
  const oauthProviders = ['drive','onedrive','dropbox'];
  const hasOAuth = oauthProviders.includes(sourceProvider) || oauthProviders.includes(destProvider);
  const credProviders = ['mega','protondrive','s3'];
  const hasCred = credProviders.includes(sourceProvider) || credProviders.includes(destProvider);
  const hint = document.getElementById('connectHint');
  if (hasOAuth && hasCred) {
    hint.innerHTML = 'Some services will open a browser for sign-in. Others will ask for credentials below.';
  } else if (hasOAuth) {
    hint.innerHTML = 'A browser tab will open for authentication. Sign in to authorize CloudMirror, then return here.';
  } else if (hasCred) {
    hint.innerHTML = 'Enter your credentials below to connect your accounts.';
  } else {
    hint.innerHTML = '';
  }

  // Check rclone first
  const statusEl = document.getElementById('rcloneStatus');
  statusEl.innerHTML = '<div class="spinner"></div> Checking rclone...';
  try {
    const resp = await fetch('/api/wizard/status');
    const data = await resp.json();
    existingRemotes = data.remotes || [];
    if (data.home_dir) window._homeDir = data.home_dir;
    if (!data.rclone_installed) {
      statusEl.innerHTML = '<span style="color:var(--orange)">rclone not found. Installing...</span>';
      const installResp = await fetch('/api/wizard/check-rclone', {method:'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}});
      const installData = await installResp.json();
      if (!installData.ok) {
        statusEl.innerHTML = '<span style="color:var(--red)">Could not install rclone. Please install manually from rclone.org</span>';
        return;
      }
      statusEl.innerHTML = '<span style="color:var(--green)">rclone installed!</span>';
    } else {
      statusEl.innerHTML = '';
    }
  } catch(e) {
    statusEl.innerHTML = '';
  }

  const items = [];
  if (sourceProvider && sourceProvider !== 'local' && sourceProvider !== 'other') {
    items.push({provider: sourceProvider, name: sourceName, display: sourceDisplayName, role: 'source'});
  }
  if (destProvider && destProvider !== 'local' && destProvider !== 'other') {
    items.push({provider: destProvider, name: destName, display: destDisplayName, role: 'dest'});
  }

  if (items.length === 0) {
    list.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-dim);">No cloud accounts need to be connected. You\'re all set!</div>';
    document.getElementById('connectNext').disabled = false;
    return;
  }

  for (const item of items) {
    const connected = existingRemotes.includes(item.name);
    const div = document.createElement('div');
    div.className = 'connect-item';
    div.id = 'connect-' + item.name;
    div.innerHTML = `
      <div class="connect-info">
        <div class="connect-icon">${providerIcons[item.provider]}</div>
        <div>
          <div class="connect-name">${item.display}</div>
          <div class="connect-status ${connected ? 'ok' : 'pending'}" id="status-${item.name}">
            ${connected ? 'Connected' : 'Not connected'}
          </div>
        </div>
      </div>
      <div id="action-${item.name}">
        ${connected
          ? '<div class="checkmark">✓</div>'
          : `<button class="btn btn-primary btn-connect" onclick="connectRemote('${item.name}','${item.provider}','${item.display}')">Connect ${item.display}</button>`
        }
      </div>
    `;
    list.appendChild(div);
  }
  checkAllConnected();
}

async function connectRemote(name, type, display, username, password) {
  const actionEl = document.getElementById('action-' + name);
  const statusEl = document.getElementById('status-' + name);
  actionEl.innerHTML = '<div class="spinner"></div>';
  statusEl.textContent = 'Connecting...';
  statusEl.className = 'connect-status pending';

  // Start polling as fallback for OAuth providers (may timeout but still succeed)
  if (['drive','onedrive','dropbox'].includes(type)) {
    startPolling(name, display, type);
  }

  try {
    const body = {name, type};
    if (username) body.username = username;
    if (password) body.password = password;
    const resp = await fetch('/api/wizard/configure-remote', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    if (data.ok) {
      statusEl.textContent = 'Connected';
      statusEl.className = 'connect-status ok';
      actionEl.innerHTML = '<div class="checkmark">✓</div>';
      if (!existingRemotes.includes(name)) existingRemotes.push(name);
    } else if (data.needs_credentials) {
      statusEl.textContent = data.msg || 'Credentials required';
      statusEl.className = 'connect-status pending';
      const userLabel = data.user_label || 'Username';
      const passLabel = data.pass_label || 'Password';
      actionEl.innerHTML = `
        <div style="display:flex;flex-direction:column;gap:8px;min-width:220px;">
          <input class="form-input" id="cred-user-${name}" type="text" placeholder="${userLabel}" style="padding:8px 12px;font-size:0.8rem;">
          <input class="form-input" id="cred-pass-${name}" type="password" placeholder="${passLabel}" style="padding:8px 12px;font-size:0.8rem;">
          <button class="btn btn-primary btn-connect" onclick="connectRemote('${name}','${type}','${display}', document.getElementById('cred-user-${name}').value, document.getElementById('cred-pass-${name}').value)">Connect</button>
        </div>`;
    } else {
      statusEl.textContent = data.msg || 'Failed to connect';
      statusEl.className = 'connect-status pending';
      actionEl.innerHTML = `<button class="btn btn-primary btn-connect" onclick="connectRemote('${name}','${type}','${display}')">Retry</button>`;
    }
  } catch(e) {
    if (['drive','onedrive','dropbox'].includes(type)) {
      statusEl.textContent = 'Waiting for authorization...';
      statusEl.className = 'connect-status pending';
    } else {
      statusEl.textContent = 'Failed to connect';
      statusEl.className = 'connect-status pending';
      actionEl.innerHTML = `<button class="btn btn-primary btn-connect" onclick="connectRemote('${name}','${type}','${display}')">Retry</button>`;
    }
  }
  checkAllConnected();
}

function checkAllConnected() {
  const items = document.querySelectorAll('.connect-item');
  let allOk = true;
  items.forEach(item => {
    const status = item.querySelector('.connect-status');
    if (!status.classList.contains('ok')) allOk = false;
  });
  document.getElementById('connectNext').disabled = !allOk;
}

// Poll for remote connection (for OAuth flow)
let pollInterval = null;
function startPolling(name, display, type) {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch('/api/wizard/check-remote', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
        body: JSON.stringify({name})
      });
      const data = await resp.json();
      if (data.configured) {
        clearInterval(pollInterval);
        pollInterval = null;
        const statusEl = document.getElementById('status-' + name);
        const actionEl = document.getElementById('action-' + name);
        if (statusEl) {
          statusEl.textContent = 'Connected';
          statusEl.className = 'connect-status ok';
        }
        if (actionEl) {
          actionEl.innerHTML = '<div class="checkmark">✓</div>';
        }
        if (!existingRemotes.includes(name)) existingRemotes.push(name);
        checkAllConnected();
      }
    } catch(e) {}
  }, 2000);
}

// Build summary
function buildSummary() {
  const card = document.getElementById('summaryCard');
  const srcSub = document.getElementById('sourceSubfolder').value.trim();
  const dstSub = document.getElementById('destSubfolder').value.trim();
  const excludes = document.getElementById('excludePatterns').value.trim();
  const bwLimit = document.getElementById('bwLimit').value.trim();
  const speedLabels = {'4': 'Normal (4 files)', '8': 'Fast (8 files)', '16': 'Maximum (16 files)'};
  const useChecksum = document.getElementById('useChecksum').checked;

  let srcPath = getSourcePath();
  let dstPath = getDestPath();

  card.innerHTML = `
    <div class="summary-row">
      <span class="summary-label">Source</span>
      <span class="summary-value">${esc(sourceDisplayName)}${srcSub ? ' / ' + esc(srcSub) : ''}</span>
    </div>
    <div class="summary-row">
      <span class="summary-label">Destination</span>
      <span class="summary-value">${esc(destDisplayName)}${dstSub ? ' / ' + esc(dstSub) : ''}</span>
    </div>
    <div class="summary-row">
      <span class="summary-label">Speed</span>
      <span class="summary-value">${esc(speedLabels[selectedSpeed])}</span>
    </div>
    ${excludes ? `<div class="summary-row">
      <span class="summary-label">Excluding</span>
      <span class="summary-value">${esc(excludes)}</span>
    </div>` : ''}
    ${bwLimit ? `<div class="summary-row">
      <span class="summary-label">Bandwidth Limit</span>
      <span class="summary-value">${esc(bwLimit)}</span>
    </div>` : ''}
    ${useChecksum ? `<div class="summary-row"><span class="summary-label">Checksum verification</span><span class="summary-value">Enabled</span></div>` : ''}
  `;
}

function showWizardError(msg) {
  const el = document.getElementById('wizardError');
  if (el) { el.textContent = msg; el.style.display = 'block'; setTimeout(() => { el.style.display = 'none'; }, 8000); }
}

function getSourcePath() {
  const srcSub = document.getElementById('sourceSubfolder').value.trim();
  if (sourceProvider === 'local') {
    const p = document.getElementById('sourcePathInput').value.trim();
    if (!p) { const errEl = document.getElementById('sourcePathError'); errEl.textContent = 'Please enter a folder path.'; errEl.style.display = 'block'; return null; }
    document.getElementById('sourcePathError').style.display = 'none';
    return srcSub ? p + '/' + srcSub : p;
  }
  if (sourceProvider === 'other') {
    const n = document.getElementById('sourceOtherInput').value.trim();
    return n + ':' + (srcSub || '');
  }
  return sourceName + ':' + (srcSub || '');
}

function getDestPath() {
  const dstSub = document.getElementById('destSubfolder').value.trim();
  if (destProvider === 'local') {
    const p = document.getElementById('destPathInput').value.trim();
    if (!p) { const errEl = document.getElementById('destPathError'); errEl.textContent = 'Please enter a folder path.'; errEl.style.display = 'block'; return null; }
    document.getElementById('destPathError').style.display = 'none';
    return dstSub ? p + '/' + dstSub : p;
  }
  if (destProvider === 'other') {
    const n = document.getElementById('destOtherInput').value.trim();
    return n + ':' + (dstSub || '');
  }
  return destName + ':' + (dstSub || '');
}

async function previewTransfer() {
  const btn = document.getElementById('previewBtn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  const result = document.getElementById('previewResult');
  try {
    const resp = await fetch('/api/wizard/preview', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify({source: getSourcePath(), dest: getDestPath(), source_type: sourceProvider, dest_type: destProvider})
    });
    const data = await resp.json();
    if (data.ok) {
      result.style.display = 'block';
      result.innerHTML = '<strong>' + esc(data.count.toLocaleString()) + ' files</strong> (' + esc(data.size) + ') will be copied.';
    } else {
      result.style.display = 'block';
      result.innerHTML = 'Could not preview: ' + esc(data.msg || 'unknown error');
    }
  } catch(e) {
    result.style.display = 'block';
    result.innerHTML = 'Preview failed. You can still start the transfer.';
  }
  btn.disabled = false;
  btn.textContent = 'Preview (see what will be copied)';
}

async function startTransfer() {
  const btn = document.getElementById('startBtn');
  if (btn.disabled) return;
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Starting transfer...';

  const safetyTimeout = setTimeout(() => {
    btn.disabled = false;
    btn.textContent = 'Start Transfer';
    showWizardError('Transfer may have started. Check the dashboard.');
  }, 30000);

  const excludes = document.getElementById('excludePatterns').value.trim();
  const excludeList = excludes ? excludes.split(',').map(e => e.trim()).filter(Boolean) : [];

  try {
    const src = getSourcePath();
    const dst = getDestPath();
    if (!src || !dst) {
      clearTimeout(safetyTimeout);
      btn.disabled = false;
      btn.textContent = 'Start Transfer';
      return;
    }
    const resp = await fetch('/api/wizard/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()},
      body: JSON.stringify({
        source: src,
        dest: dst,
        transfers: selectedSpeed,
        excludes: excludeList,
        source_type: sourceProvider,
        dest_type: destProvider,
        bw_limit: document.getElementById('bwLimit').value.trim(),
        checksum: document.getElementById('useChecksum').checked
      })
    });
    clearTimeout(safetyTimeout);
    const data = await resp.json();
    if (data.ok) {
      // Redirect to dashboard
      window.location.href = '/dashboard';
    } else {
      btn.disabled = false;
      btn.textContent = 'Start Transfer';
      showWizardError('Error: ' + (data.msg || 'Failed to start transfer'));
    }
  } catch(e) {
    clearTimeout(safetyTimeout);
    btn.disabled = false;
    btn.textContent = 'Start Transfer';
    showWizardError('Error starting transfer. Please check the console.');
  }
}
</script>
</body>
</html>
'''


# ─── Wizard API helpers ──────────────────────────────────────────────────────

def configure_remote_api(name, provider_type, username=None, password=None):
    """Configure an rclone remote non-interactively (for web wizard)."""
    if provider_type == "local":
        return {"ok": True}

    if remote_exists(name):
        return {"ok": True, "msg": "Already configured"}

    if username and not validate_rclone_input(username, "username"):
        return {"ok": False, "msg": "Invalid username"}
    if password and not validate_rclone_input(password, "password"):
        return {"ok": False, "msg": "Invalid password"}

    if provider_type == "mega":
        if not username or not password:
            return {"ok": False, "needs_credentials": True, "msg": "MEGA requires your email and password.",
                    "user_label": "Email", "pass_label": "Password"}
        result = subprocess.run(["rclone", "obscure", password], capture_output=True, text=True)
        if result.returncode != 0:
            return {"ok": False, "msg": "Failed to process credentials"}
        obscured = result.stdout.strip()
        env = os.environ.copy()
        env[f"RCLONE_CONFIG_{name.upper()}_USER"] = username
        env[f"RCLONE_CONFIG_{name.upper()}_PASS"] = obscured
        cmd = ["rclone", "config", "create", name, provider_type]
    elif provider_type == "protondrive":
        if not username or not password:
            return {"ok": False, "needs_credentials": True, "msg": "Proton Drive requires your Proton username and password.",
                    "user_label": "Username", "pass_label": "Password"}
        result = subprocess.run(["rclone", "obscure", password], capture_output=True, text=True)
        if result.returncode != 0:
            return {"ok": False, "msg": "Failed to process credentials"}
        obscured_pw = result.stdout.strip()
        env = os.environ.copy()
        env[f"RCLONE_CONFIG_{name.upper()}_USERNAME"] = username
        env[f"RCLONE_CONFIG_{name.upper()}_PASSWORD"] = obscured_pw
        cmd = ["rclone", "config", "create", name, provider_type]
    elif provider_type == "s3":
        if not username or not password:
            return {"ok": False, "needs_credentials": True,
                    "msg": "Amazon S3 requires your Access Key ID and Secret Access Key.",
                    "user_label": "Access Key ID", "pass_label": "Secret Access Key"}
        env = os.environ.copy()
        env[f"RCLONE_CONFIG_{name.upper()}_ACCESS_KEY_ID"] = username
        env[f"RCLONE_CONFIG_{name.upper()}_SECRET_ACCESS_KEY"] = password
        cmd = ["rclone", "config", "create", name, provider_type, "provider=AWS"]
    else:
        # For OAuth-based providers, rclone config create will open browser automatically
        cmd = ["rclone", "config", "create", name, provider_type]

    try:
        run_env = env if provider_type in ("s3", "mega", "protondrive") else None
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=RCLONE_CONFIG_TIMEOUT_SEC, env=run_env)
        if result.returncode == 0:
            # Validate the remote actually works
            if provider_type in ("mega", "protondrive", "s3"):
                check = subprocess.run(["rclone", "lsd", f"{name}:"], capture_output=True, text=True, timeout=RCLONE_CHECK_TIMEOUT_SEC)
                if check.returncode != 0:
                    # Remove the broken remote
                    subprocess.run(["rclone", "config", "delete", name], capture_output=True, text=True)
                    error_msg = check.stderr.strip().split('\n')[0] if check.stderr else "Invalid credentials"
                    # Simplify error message
                    if 'login' in error_msg.lower() or 'auth' in error_msg.lower() or 'credential' in error_msg.lower() or 'password' in error_msg.lower():
                        error_msg = "Invalid username or password. Please check your credentials and try again."
                    return {"ok": False, "msg": error_msg}
            return {"ok": True}
        else:
            return {"ok": False, "msg": _sanitize_rclone_error(result.stderr)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "Configuration timed out. Please try again."}
    except Exception as e:
        return {"ok": False, "msg": _sanitize_rclone_error(str(e))}


# ─── HTTP Server ──────────────────────────────────────────────────────────────

def pause_rclone():
    with _transfer_lock:
        return _pause_rclone_locked()


def _pause_rclone_locked():
    global rclone_pid
    if not rclone_pid:
        return {"ok": False, "msg": "No tracked rclone process"}
    try:
        os.kill(rclone_pid, signal.SIGTERM)
        old_pid = rclone_pid
        rclone_pid = None
        time.sleep(1)
        scan_full_log()
        return {"ok": True, "msg": f"Stopped rclone (PID {old_pid})"}
    except (ProcessLookupError, OSError):
        rclone_pid = None
        return {"ok": False, "msg": "rclone process not found"}


def resume_rclone():
    with _transfer_lock:
        return _resume_rclone_locked()


def _resume_rclone_locked():
    global RCLONE_CMD, rclone_pid
    if not RCLONE_CMD:
        with state_lock:
            RCLONE_CMD = state.get("rclone_cmd", [])
    if not RCLONE_CMD:
        return {"ok": False, "msg": "No transfer configured. Please set up a transfer first."}
    if is_rclone_running():
        return {"ok": False, "msg": "rclone is already running"}
    try:
        proc = subprocess.Popen(
            RCLONE_CMD,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        rclone_pid = proc.pid
        return {"ok": True, "msg": f"Started rclone (PID {proc.pid})"}
    except Exception as e:
        return {"ok": False, "msg": f"Failed to start: {str(e)}"}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        # Only allow CORS from localhost to prevent cross-site request forgery
        # from malicious pages that might try to start transfers.
        origin = self.headers.get("Origin", "")
        allowed_origins = {f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"}
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_html(self, html):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"csrf_token={CSRF_TOKEN}; Path=/; SameSite=Strict")
        self.end_headers()
        self.wfile.write(html.encode())

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
        # Cap request size to prevent memory exhaustion from oversized payloads.
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_REQUEST_BODY_BYTES:
            return None
        if length > 0:
            try:
                return json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError):
                return None
        return {}

    def do_GET(self):
        if not self._check_host():
            return
        global TRANSFER_ACTIVE
        if self.path == "/api/status":
            self._send_json(parse_current())
        elif self.path == "/api/wizard/status":
            self._send_json({
                "rclone_installed": find_rclone() is not None,
                "remotes": get_existing_remotes(),
                "home_dir": os.path.expanduser("~"),
            })
        elif self.path == "/api/history":
            history = []
            for f in sorted(os.listdir(_CM_DIR)):
                if f.endswith('_state.json'):
                    try:
                        with open(os.path.join(_CM_DIR, f)) as sf:
                            s = json.load(sf)
                            history.append({
                                "id": f.replace('cloudmirror_','').replace('_state.json',''),
                                "label": s.get("transfer_label", TRANSFER_LABEL),
                                "sessions": len(s.get("sessions", [])),
                                "cmd": s.get("rclone_cmd", []),
                            })
                    except Exception:
                        pass
            self._send_json(history)
        elif self.path == "/dashboard":
            self._send_html(HTML)
        elif self.path == "/wizard":
            self._send_html(WIZARD_HTML)
        elif self.path == "/":
            if is_rclone_running() or TRANSFER_ACTIVE:
                self._send_html(HTML)
            else:
                self._send_html(WIZARD_HTML)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self._check_host():
            return
        if not self._check_csrf():
            return
        if self.path == "/api/pause":
            self._send_json(pause_rclone())
        elif self.path == "/api/resume":
            self._send_json(resume_rclone())
        elif self.path == "/api/wizard/check-rclone":
            path = find_rclone()
            if path:
                self._send_json({"ok": True, "path": path})
            else:
                # Try to install
                try:
                    system = platform.system().lower()
                    if system == "darwin" and shutil.which("brew"):
                        subprocess.run(["brew", "install", "rclone"], capture_output=True, timeout=RCLONE_INSTALL_TIMEOUT_SEC)
                    elif system in ("darwin", "linux"):
                        subprocess.run(
                            ["bash", "-c", "curl -s https://rclone.org/install.sh | sudo bash"],
                            capture_output=True, timeout=RCLONE_INSTALL_TIMEOUT_SEC
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
                    result = subprocess.run(["rclone", "size", source, "--json"], capture_output=True, text=True, timeout=RCLONE_PREVIEW_TIMEOUT_SEC)
                    if result.returncode == 0:
                        data = json.loads(result.stdout)
                        size_bytes = data.get("bytes", 0)
                        if size_bytes > 1073741824:
                            size_str = f"{size_bytes/1073741824:.2f} GiB"
                        elif size_bytes > 1048576:
                            size_str = f"{size_bytes/1048576:.1f} MiB"
                        else:
                            size_str = f"{size_bytes/1024:.0f} KiB"
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
            result = start_transfer_from_wizard(body)
            self._send_json(result)
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self.headers.get("Origin", "")
        allowed_origins = {f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"}
        if origin in allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def start_transfer_from_wizard(body):
    """Start a transfer from the web wizard.

    Flow: validate inputs -> set up per-transfer log/state paths ->
    build rclone command with performance flags -> launch rclone as a
    detached subprocess (start_new_session=True so it survives if
    CloudMirror exits) -> return PID to the wizard for dashboard redirect.
    """
    with _transfer_lock:
        return _start_transfer_from_wizard_locked(body)


def _start_transfer_from_wizard_locked(body):
    global RCLONE_CMD, TRANSFER_ACTIVE

    if TRANSFER_ACTIVE or is_rclone_running():
        return {"ok": False, "msg": "A transfer is already running"}

    source = body.get("source", "")
    dest = body.get("dest", "")
    try:
        transfers = int(body.get("transfers", "8"))
        if not (1 <= transfers <= MAX_TRANSFERS):
            transfers = 8
    except (ValueError, TypeError):
        transfers = 8
    excludes = body.get("excludes", [])
    bw_limit = body.get("bw_limit", "")
    source_type = body.get("source_type", "")
    dest_type = body.get("dest_type", "")

    if not source or not dest:
        return {"ok": False, "msg": "Missing source or destination"}

    # Reject values starting with "-" to prevent rclone flag injection
    if not validate_rclone_input(source, "source"):
        return {"ok": False, "msg": "Invalid input"}
    if not validate_rclone_input(dest, "dest"):
        return {"ok": False, "msg": "Invalid input"}
    for excl in excludes:
        if not validate_exclude_pattern(excl):
            return {"ok": False, "msg": "Invalid input"}

    # Verify local paths exist to catch typos early and prevent path traversal
    if source_type == "local" and not os.path.exists(source):
        return {"ok": False, "msg": f"Path not found: {source}"}
    if dest_type == "local" and not os.path.exists(dest):
        try:
            os.makedirs(dest, exist_ok=True)
        except OSError:
            return {"ok": False, "msg": f"Cannot create folder: {dest}. Please check the path."}

    set_transfer_paths(source, dest)

    RCLONE_CMD = [
        "rclone", "copy", source, dest,
        f"--transfers={transfers}",
        "--checkers=16",
        f"--log-file={LOG_FILE}",
        "--log-level=INFO",
        "--stats=10s",
        "--stats-log-level=INFO",
    ]

    # Cloud-to-cloud transfers benefit from larger chunks and buffers
    # since the bottleneck is API calls, not disk I/O.
    if source_type not in ("local",) and dest_type not in ("local",):
        RCLONE_CMD.extend([
            "--drive-chunk-size=256M",
            "--buffer-size=128M",
            "--multi-thread-streams=16",
        ])

    for excl in excludes:
        if excl:
            RCLONE_CMD.append(f"--exclude={excl}/**")

    if bw_limit and validate_rclone_input(bw_limit, "bw_limit"):
        RCLONE_CMD.append(f"--bwlimit={bw_limit}")

    if body.get("checksum"):
        RCLONE_CMD.append("--checksum")

    # S6: Save RCLONE_CMD to state but strip credential flags
    safe_cmd = [arg for arg in RCLONE_CMD if not any(secret in arg.lower() for secret in ['password', 'pass', 'user', 'token', 'key=', 'secret'])]
    with state_lock:
        state["rclone_cmd"] = safe_cmd
        state["transfer_label"] = TRANSFER_LABEL
        save_state(state)

    try:
        proc = subprocess.Popen(
            RCLONE_CMD,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        global rclone_pid
        rclone_pid = proc.pid
        TRANSFER_ACTIVE = True
        return {"ok": True, "pid": proc.pid}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def start_dashboard(start_rclone=False):
    """Start the web dashboard and optionally the rclone process."""
    global state, TRANSFER_ACTIVE, RCLONE_CMD, rclone_pid, PORT, LOG_FILE

    # Load RCLONE_CMD from state if not set (enables resume after restart)
    with state_lock:
        if not RCLONE_CMD and "rclone_cmd" in state:
            RCLONE_CMD = state["rclone_cmd"]
            # Restore LOG_FILE from the saved command
            for arg in RCLONE_CMD:
                if arg.startswith("--log-file="):
                    LOG_FILE = arg.split("=", 1)[1]
                    break

    # Initial full log scan
    print()
    print("  Scanning transfer log...")
    scan_full_log()
    session_count = len(state.get("sessions", []))
    if session_count > 0:
        print(f"  Found {session_count} previous session(s)")

    # Start background scanner
    scanner = threading.Thread(target=background_scanner, daemon=True)
    scanner.start()

    # Start rclone if requested
    if start_rclone and RCLONE_CMD:
        print("  Starting file transfer...")
        proc = subprocess.Popen(
            RCLONE_CMD,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        rclone_pid = proc.pid
        print(f"  Transfer started (PID {proc.pid})")
        TRANSFER_ACTIVE = True

    print()
    print(f"  CloudMirror: http://localhost:{PORT}")
    print()
    if TRANSFER_ACTIVE:
        print("  Open the link above in your browser to monitor progress.")
    else:
        print("  Open the link above in your browser to start the setup wizard.")
    print("  Press Ctrl+C to stop the server.")
    print()

    server = None
    for try_port in range(PORT, PORT + 5):
        try:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", try_port), Handler)
            if try_port != PORT:
                print(f"  Port {PORT} was busy, using port {try_port} instead.")
                PORT = try_port
            break
        except OSError as e:
            if ("Address already in use" in str(e) or e.errno == 48) and try_port < PORT + 4:
                continue
            if "Address already in use" in str(e) or e.errno == 48:
                print(f"\n  Error: Ports {PORT}-{PORT+4} are all in use.")
                print(f"  Please stop the other process(es) and try again.\n")
                sys.exit(1)
            raise
    if server is None:
        print(f"\n  Error: Could not bind to any port in range {PORT}-{PORT+4}.\n")
        sys.exit(1)
    # Try to open browser automatically (after port binding succeeds)
    try:
        webbrowser.open(f"http://localhost:{PORT}")
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  CloudMirror stopped.")
        if TRANSFER_ACTIVE:
            print("  (The file transfer continues in the background)")
        print()


def parse_cli_args(args):
    """Parse CLI arguments for advanced usage: cloudmirror.py source: dest: [flags]"""
    global RCLONE_CMD

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
        print("Usage: python3 cloudmirror.py <source> <destination> [--flags]")
        print("Example: python3 cloudmirror.py onedrive: gdrive:backup --transfers=8")
        print()
        print("Or just run without arguments for the interactive wizard:")
        print("  python3 cloudmirror.py")
        sys.exit(1)

    set_transfer_paths(source, dest)

    RCLONE_CMD = [
        "rclone", "copy", source, dest,
        f"--log-file={LOG_FILE}",
        "--log-level=INFO",
        "--stats=10s",
        "--stats-log-level=INFO",
    ] + extra_flags

    # Add default transfers if not specified
    if not any(f.startswith("--transfers") for f in extra_flags):
        RCLONE_CMD.append("--transfers=8")
    if not any(f.startswith("--checkers") for f in extra_flags):
        RCLONE_CMD.append("--checkers=16")


def _signal_handler(signum, frame):
    print("\n  CloudMirror stopped.")
    if TRANSFER_ACTIVE:
        print("  (The file transfer continues in the background)")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _signal_handler)
    args = sys.argv[1:]

    if len(args) == 0:
        # Web wizard mode - serve wizard in browser
        print()
        print("  ╔══════════════════════════════════════════════════╗")
        print("  ║              Welcome to CloudMirror              ║")
        print("  ║                                                  ║")
        print("  ║   Starting web setup wizard...                   ║")
        print("  ╚══════════════════════════════════════════════════╝")
        if platform.system() == "Windows":
            print("  Note: Some features (pause/resume) may not work on Windows.")
            print("  For best results, use macOS or Linux.")
            print()
        start_dashboard(start_rclone=False)
    else:
        # CLI mode for advanced users
        ensure_rclone()
        parse_cli_args(args)
        print()
        print("  CloudMirror - Advanced Mode")
        print(f"  Command: {' '.join(RCLONE_CMD)}")
        start_dashboard(start_rclone=True)
