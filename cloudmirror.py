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
import platform
import shutil
import hashlib
import webbrowser
from datetime import datetime, timedelta

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
RE_CHECKS = re.compile(r"Checks:\s+(\d+)\s*/\s*(\d+)")
RE_ERRORS = re.compile(r"Errors:\s+(\d+)")
RE_SPEED = re.compile(r"([\d.]+)\s*([KMGT]i?B)/s", re.I)
RE_COPIED = re.compile(r"INFO\s+:\s+(.+?):\s+Copied\s+\(new\)")
RE_ACTIVE = re.compile(r"\*\s+(.+?):\s+(\d+)%\s*/(\S+),\s*(\S+/s),\s*(\S+)")
RE_ACTIVE2 = re.compile(r"\*\s+(.+?):\s+(\d+)%\s*/(\S+),\s*(\S+/s)")
RE_ACTIVE3 = re.compile(r"\*\s+(.+?):\s+transferring")

_CM_DIR = os.path.join(os.path.expanduser("~"), ".cloudmirror")
os.makedirs(_CM_DIR, mode=0o700, exist_ok=True)
LOG_FILE = os.path.join(_CM_DIR, "cloudmirror.log")
STATE_FILE = os.path.join(_CM_DIR, "cloudmirror_state.json")
PORT = 8787
TRANSFER_LABEL = "Source -> Destination"

# rclone command - set dynamically by wizard or CLI args
RCLONE_CMD = []
TRANSFER_ACTIVE = False
rclone_pid = None


def is_rclone_running():
    global rclone_pid
    if rclone_pid:
        try:
            os.kill(rclone_pid, 0)
            return True
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
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save state: {e}")


# ─── Byte conversion helpers ─────────────────────────────────────────────────

def to_bytes(size_str):
    """Convert '90.054 GiB' or '103.010 MiB' to bytes."""
    m = re.match(r"([\d.]+)\s*(\S+)", size_str.strip())
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
    m = re.findall(r"(\d+)h", s)
    if m:
        sec += int(m[0]) * 3600
    m = re.findall(r"(\d+)m", s)
    if m:
        sec += int(m[0]) * 60
    m = re.findall(r"([\d.]+)s", s)
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


# ─── Log scanner with session detection ──────────────────────────────────────

state_lock = threading.Lock()
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

    with open(LOG_FILE, "r", errors="replace") as f:
        content = f.read()

    lines = content.split("\n")

    sessions = []
    current_session = None
    prev_elapsed = -1
    file_types = {}
    total_copied = 0
    last_ts = None
    prev_ts = None

    # Snapshot values from just before a session boundary, so the previous
    # session's final stats are captured before rclone resets its counters.
    prev_transferred_bytes = 0
    prev_total_bytes = 0
    prev_files_done = 0
    prev_files_total = 0

    for line in lines:
        ts_match = re.match(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})", line)
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

        m_files = RE_TRANSFERRED_FILES.search(line)
        if m_files:
            if current_session is not None:
                prev_files_done = current_session.get("final_files_done", 0)
                prev_files_total = current_session.get("final_files_total", 0)
                current_session["final_files_done"] = int(m_files.group(1))
                current_session["final_files_total"] = int(m_files.group(2))

        m_elapsed = RE_ELAPSED.search(line)
        if m_elapsed:
            elapsed_str = m_elapsed.group(1).strip()
            elapsed_sec = parse_elapsed(elapsed_str)

            # Session boundary: elapsed dropped >50% means rclone restarted.
            # Finalize the previous session with its pre-reset values and
            # back-calculate the new session's true start time.
            if prev_elapsed > 60 and elapsed_sec < prev_elapsed * 0.5:
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

        m_copied = RE_COPIED.search(line)
        if m_copied:
            fname = m_copied.group(1).strip()
            total_copied += 1
            ext_parts = fname.rsplit(".", 1)
            if len(ext_parts) > 1:
                ext = ext_parts[1].lower()
                file_types[ext] = file_types.get(ext, 0) + 1
            else:
                file_types["other"] = file_types.get("other", 0) + 1

    if current_session:
        current_session["end_time"] = current_session.get("last_ts", "")
        sessions.append(current_session)

    cumulative_bytes = 0
    cumulative_files = 0
    cumulative_elapsed = 0
    for s in sessions[:-1]:
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
    elif sessions:
        original_total = max((s.get("session_total_bytes", 0) or 0) for s in sessions)
        original_files = max((s.get("final_files_total", 0) or 0) for s in sessions)
        # Fetch real size in background
        def _fetch_source_size():
            try:
                src = RCLONE_CMD[2] if len(RCLONE_CMD) > 2 else ""
                if not src:
                    return
                result = subprocess.run(
                    ["rclone", "size", src, "--json"],
                    capture_output=True, text=True, timeout=600
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    with state_lock:
                        state["source_size_bytes"] = data.get("bytes", 0)
                        state["source_size_files"] = data.get("count", 0)
                    save_state(state)
            except Exception:
                pass
        threading.Thread(target=_fetch_source_size, daemon=True).start()

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
            for i, s in enumerate(sessions)
        ]
        state["cumulative_transferred_bytes"] = cumulative_bytes
        state["cumulative_files_done"] = cumulative_files
        state["cumulative_elapsed_sec"] = cumulative_elapsed
        state["original_total_bytes"] = original_total
        state["original_total_files"] = original_files
        state["all_file_types"] = file_types
        state["total_copied_count"] = total_copied
        save_state(state)


def parse_current():
    """Parse current stats from the tail of the log, combined with session state.

    This is called every few seconds by the dashboard via /api/status.
    It reads the last 16KB of the log (for current rclone stats), then
    combines those with cumulative session data from scan_full_log() to
    produce global progress numbers that span all sessions.
    """
    if not os.path.exists(LOG_FILE):
        return {"error": "Log file not found", "rclone_running": is_rclone_running()}

    result = {
        "speed": None, "eta": None, "session_elapsed": "",
        "session_files_done": 0, "session_files_total": 0,
        "errors": 0, "checks_done": 0, "checks_total": 0, "listed": 0,
    }

    # Read only the tail of the log for current-session stats (fast).
    with open(LOG_FILE, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 16000))
        tail = f.read().decode("utf-8", errors="replace")

    lines = tail.split("\n")

    cur_transferred_str = ""
    cur_total_str = ""
    cur_transferred_bytes = 0
    cur_total_bytes = 0

    re_full_transfer = re.compile(r"Transferred:\s+([\d.]+\s+\S+)\s*/\s*([\d.]+\s+\S+),\s*(\d+)%,\s*([\d.]+\s*\S+/s),\s*ETA\s*(\S+)")
    for line in lines:
        m = re_full_transfer.search(line)
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

        m5 = re.search(r"Checks:\s+(\d+)\s*/\s*(\d+).+Listed\s+(\d+)", line)
        if m5:
            result["checks_done"] = int(m5.group(1))
            result["checks_total"] = int(m5.group(2))
            result["listed"] = int(m5.group(3))

    # Parse active transfers
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
    result["active"] = list(seen.values())

    # Recent files
    recent_files = []
    chunk_size = 100000
    max_chunk = 2000000
    with open(LOG_FILE, "rb") as f:
        f.seek(0, 2)
        fsize = f.tell()
        while chunk_size <= max_chunk and len(recent_files) < 15:
            f.seek(max(0, fsize - chunk_size))
            chunk = f.read().decode("utf-8", errors="replace")
            recent_files = []
            for line in chunk.split("\n"):
                m = re.search(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+INFO\s+:\s+(.+?):\s+Copied\s+\(new\)", line)
                if m:
                    recent_files.append({"name": m.group(2).strip(), "time": m.group(1).split(" ")[1]})
            if len(recent_files) >= 15 or chunk_size >= fsize:
                break
            chunk_size *= 4
    result["recent_files"] = recent_files[-15:][::-1]

    # Error messages
    error_msgs = []
    with open(LOG_FILE, "rb") as f:
        f.seek(0, 2)
        fsize = f.tell()
        f.seek(max(0, fsize - 100000))
        err_tail = f.read().decode("utf-8", errors="replace")
    for line in err_tail.split("\n"):
        if "ERROR" in line and "Errors:" not in line:
            m = re.search(r"\d{2}:\d{2}:\d{2}\s+ERROR\s+:\s+(.+)", line)
            if m:
                msg = m.group(1).strip()
                if msg not in error_msgs:
                    error_msgs.append(msg)
    result["error_messages"] = error_msgs[-5:]

    # Process status
    result["finished"] = not is_rclone_running()

    # Speed/progress history from ENTIRE log
    try:
        with open(LOG_FILE, "rb") as f:
            full_log = f.read().decode("utf-8", errors="replace")
        speed_hist = []
        pct_hist = []
        files_hist = []
        prev_el = -1
        cumul_bytes_offset = 0
        cumul_files_offset = 0
        session_max_bytes = 0
        session_max_files = 0
        session_total_bytes = 0
        first_session_total = 0

        for line in full_log.split("\n"):
            m_spd = RE_TRANSFERRED_BYTES.search(line)
            if m_spd:
                cur_bytes = to_bytes(m_spd.group(1))
                cur_total = to_bytes(m_spd.group(2))
                if first_session_total == 0:
                    first_session_total = cur_total
                session_total_bytes = cur_total
                session_max_bytes = max(session_max_bytes, cur_bytes)

                if first_session_total > 0:
                    global_pct_val = (cumul_bytes_offset + cur_bytes) / first_session_total * 100
                    pct_hist.append(round(min(global_pct_val, 100), 1))

                spd_str = m_spd.group(4)
                sm = RE_SPEED.match(spd_str)
                if sm:
                    v = float(sm.group(1))
                    u = sm.group(2).upper()
                    if u.startswith("K"): v /= 1024
                    elif u.startswith("G"): v *= 1024
                    speed_hist.append(round(v, 3))

            m_fl = re.search(r"Transferred:\s+(\d+)\s*/\s*\d+,\s*\d+%", line)
            if m_fl:
                cur_files = int(m_fl.group(1))
                session_max_files = max(session_max_files, cur_files)
                files_hist.append(cumul_files_offset + cur_files)

            m_el = RE_ELAPSED.search(line)
            if m_el:
                el = parse_elapsed(m_el.group(1).strip())
                # Session boundary in chart data: shift cumulative offsets
                # and insert None to create a visual gap in the chart.
                if prev_el > 60 and el < prev_el * 0.5:
                    cumul_bytes_offset += session_max_bytes
                    cumul_files_offset += session_max_files
                    session_max_bytes = 0
                    session_max_files = 0
                    speed_hist.append(None)
                    pct_hist.append(None)
                    files_hist.append(None)
                prev_el = el

        def downsample(arr, target=200):
            if len(arr) <= target:
                return arr
            step = len(arr) / target
            result = []
            for i in range(target):
                idx = int(i * step)
                result.append(arr[idx])
            return result

        result["speed_history"] = downsample(speed_hist)
        result["pct_history"] = downsample(pct_hist)
        result["files_history"] = downsample(files_hist)
    except Exception:
        result["speed_history"] = []
        result["pct_history"] = []
        result["files_history"] = []

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
            global_total = cur_total_bytes + cumul_bytes

        global_files_done = cumul_files + result.get("session_files_done", 0)
        if orig_files > 0:
            global_files_total = orig_files
        else:
            global_files_total = result.get("session_files_total", 0) + cumul_files

        session_elapsed_sec = parse_elapsed(result.get("session_elapsed", ""))
        global_elapsed_sec = cumul_elapsed + session_elapsed_sec

        global_pct = 0
        if global_total > 0:
            global_pct = round(global_transferred / global_total * 100, 1)
            global_pct = min(global_pct, 100)

        files_pct = 0
        if global_files_total > 0:
            files_pct = round(global_files_done / global_files_total * 100, 1)

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
                    if gap > 60:
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
                    result["uptime_pct"] = round(global_elapsed_sec / wall_sec * 100, 1)
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
        time.sleep(30)


# ─── HTML ─────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudMirror Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { scrollbar-width: none; }

  :root {
    --bg: #060a14;
    --card: #0d1220;
    --card-border: #151d35;
    --text: #c8d3e8;
    --text-dim: #7a8baa;
    --text-muted: #6a7a9a;
    --blue: #3b82f6;
    --blue-light: #60a5fa;
    --green: #22c55e;
    --orange: #f59e0b;
    --red: #ef4444;
    --purple: #a78bfa;
    --cyan: #22d3ee;
    --pink: #f472b6;
    --yellow: #facc15;
    --chart-grid: #151d35;
    --chart-text: #2a3555;
    --mini-bar-bg: #0a0f1e;
    --big-track-bg: #0a0f1e;
    --big-track-border: #151d35;
    --prev-fill-start: #1e3a5f;
    --prev-fill-end: #1d4ed8;
    --shimmer: rgba(255,255,255,0.1);
  }

  [data-theme="light"] {
    --bg: #f0f2f5;
    --card: #ffffff;
    --card-border: #e2e8f0;
    --text: #1e293b;
    --text-dim: #64748b;
    --text-muted: #94a3b8;
    --blue: #2563eb;
    --blue-light: #3b82f6;
    --green: #16a34a;
    --orange: #d97706;
    --red: #dc2626;
    --purple: #7c3aed;
    --cyan: #0891b2;
    --pink: #db2777;
    --yellow: #ca8a04;
    --chart-grid: #e2e8f0;
    --chart-text: #94a3b8;
    --mini-bar-bg: #e2e8f0;
    --big-track-bg: #e2e8f0;
    --big-track-border: #cbd5e1;
    --prev-fill-start: #93c5fd;
    --prev-fill-end: #3b82f6;
    --shimmer: rgba(255,255,255,0.4);
  }
  [data-theme="light"] .header h1 { color: #0f172a; }
  [data-theme="light"] .big-pct { color: #0f172a; }
  [data-theme="light"] .stat-value { color: #0f172a; }
  [data-theme="light"] .tl-dot { background: var(--bg); }
  [data-theme="light"] .tl-pause-inner { background: rgba(245,158,11,0.08); border-color: rgba(245,158,11,0.3); }
  [data-theme="light"] .transfer-item:hover { background: rgba(0,0,0,0.02); }
  [data-theme="light"] .type-badge { background: rgba(0,0,0,0.04); }

  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 20px 24px;
    overflow-x: hidden;
  }

  .container { max-width: 1200px; margin: 0 auto; }

  .header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--card-border);
  }
  .header-left { display: flex; align-items: center; gap: 12px; }
  .header h1 { font-size: 1.3rem; font-weight: 700; color: #fff; letter-spacing: -0.03em; }

  .status-badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 12px; border-radius: 20px; font-size: 0.7rem;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .status-badge.active { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: var(--green); }
  .status-badge.paused { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); color: var(--orange); }
  .status-badge.stopped { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: var(--red); }

  .status-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
  .status-badge.active .status-dot { animation: pulse 2s infinite; }
  @keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(34,197,94,0.4); }
    50% { opacity: 0.6; box-shadow: 0 0 0 5px rgba(34,197,94,0); }
  }

  .session-badge {
    font-size: 0.65rem; color: var(--purple); background: rgba(167,139,250,0.1);
    border: 1px solid rgba(167,139,250,0.2); padding: 3px 10px; border-radius: 12px;
  }

  .header-right { font-size: 0.75rem; color: var(--text-dim); text-align: right; }

  .theme-toggle {
    background: var(--card); border: 1px solid var(--card-border); border-radius: 8px;
    padding: 6px 10px; cursor: pointer; font-size: 1rem; line-height: 1;
    color: var(--text); transition: all 0.2s;
    min-width: 44px; min-height: 44px;
    display: flex; align-items: center; justify-content: center;
  }
  .theme-toggle:hover { border-color: var(--blue); }
  .header-right div { margin-bottom: 2px; }

  /* Big progress */
  .big-progress {
    margin-bottom: 24px; background: var(--card);
    border: 1px solid var(--card-border); border-radius: 16px; padding: 24px;
  }
  .big-progress-header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 14px; }
  .big-pct { font-size: 3.2rem; font-weight: 800; color: #fff; letter-spacing: -0.04em; line-height: 1; }
  .big-pct .unit { font-size: 1.6rem; color: var(--blue-light); }
  .big-detail { font-size: 0.85rem; color: var(--text-dim); text-align: right; }
  .big-detail span { color: var(--text); font-weight: 500; }
  .big-detail .session-note { font-size: 0.7rem; color: var(--text-muted); margin-top: 4px; }

  .big-track { height: 36px; background: var(--mini-bar-bg); border-radius: 18px; overflow: hidden; position: relative; border: 1px solid var(--card-border); }
  .big-fill {
    height: 100%; border-radius: 18px; position: relative; min-width: 4px; transition: width 2s ease;
    background: linear-gradient(90deg, #1d4ed8 0%, var(--blue) 40%, var(--blue-light) 100%);
  }
  .big-fill::after {
    content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.1) 50%, transparent 100%);
    animation: shimmer 3s infinite;
  }
  /* Previous sessions portion overlay */
  .prev-fill {
    position: absolute; top: 0; left: 0; height: 100%; border-radius: 18px 0 0 18px;
    background: linear-gradient(90deg, #1e3a5f 0%, #1d4ed8 100%);
    opacity: 0.6; pointer-events: none; transition: width 2s ease;
  }

  @keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(200%); } }

  .big-bars { display: flex; gap: 16px; margin-top: 14px; }
  .sub-bar-wrap { flex: 1; }
  .sub-bar-label { display: flex; justify-content: space-between; font-size: 0.7rem; color: var(--text-dim); margin-bottom: 4px; }
  .sub-bar-label span { color: var(--text); font-weight: 500; }
  .sub-track { height: 8px; background: var(--mini-bar-bg); border-radius: 4px; overflow: hidden; }
  .sub-fill { height: 100%; border-radius: 4px; transition: width 2s ease; }
  .sub-fill.files { background: linear-gradient(90deg, #7c3aed, var(--purple)); }
  .sub-fill.checks { background: linear-gradient(90deg, #0891b2, var(--cyan)); }

  /* Stats grid */
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
  @media (max-width: 900px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }

  .stat-card {
    background: var(--card); border: 1px solid var(--card-border); border-radius: 12px;
    padding: 16px; text-align: center; transition: border-color 0.2s;
  }
  .stat-card:hover { border-color: var(--blue); }
  .stat-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-dim); margin-bottom: 6px; }
  .stat-value { font-size: 1.4rem; font-weight: 700; color: #fff; line-height: 1.2; }
  .stat-sub { font-size: 0.65rem; color: var(--text-dim); margin-top: 3px; }
  .stat-value.blue { color: var(--blue-light); }
  .stat-value.green { color: var(--green); }
  .stat-value.orange { color: var(--orange); }
  .stat-value.purple { color: var(--purple); }
  .stat-value.cyan { color: var(--cyan); }
  .stat-value.red { color: var(--red); }
  .stat-value.pink { color: var(--pink); }
  .stat-value.yellow { color: var(--yellow); }

  /* Session timeline */
  .timeline-section {
    background: var(--card); border: 1px solid var(--card-border); border-radius: 14px;
    padding: 18px; margin-bottom: 24px;
  }
  .timeline-section h3 {
    font-size: 0.75rem; font-weight: 600; color: var(--text-dim);
    text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 14px;
  }

  .timeline { position: relative; padding-left: 24px; }
  .timeline::before {
    content: ''; position: absolute; left: 7px; top: 4px; bottom: 4px;
    width: 2px; background: var(--card-border);
  }

  .tl-item { position: relative; padding-bottom: 16px; }
  .tl-item:last-child { padding-bottom: 0; }
  .tl-dot {
    position: absolute; left: -20px; top: 3px; width: 10px; height: 10px;
    border-radius: 50%; border: 2px solid; background: var(--bg);
  }
  .tl-dot.active { border-color: var(--green); background: var(--green); }
  .tl-dot.done { border-color: var(--blue); }
  .tl-dot.pause { border-color: var(--orange); }

  .tl-header { display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }
  .tl-title { font-size: 0.8rem; font-weight: 600; color: var(--text); }
  .tl-time { font-size: 0.65rem; color: var(--text-dim); }
  .tl-stats { font-size: 0.7rem; color: var(--text-dim); line-height: 1.6; }
  .tl-stats span { color: var(--text); font-weight: 500; }

  .tl-pause {
    position: relative; padding-bottom: 16px; padding-left: 0;
    margin-left: -24px; padding-left: 24px;
  }
  .tl-pause-inner {
    background: rgba(245,158,11,0.05); border: 1px dashed rgba(245,158,11,0.2);
    border-radius: 8px; padding: 8px 12px; font-size: 0.7rem; color: var(--orange);
  }

  /* Charts */
  .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 700px) { .charts-row { grid-template-columns: 1fr; } }
  .chart-card { background: var(--card); border: 1px solid var(--card-border); border-radius: 14px; padding: 18px; }
  .chart-card h3 { font-size: 0.75rem; font-weight: 600; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 14px; }
  .chart-container { height: 160px; position: relative; }
  .chart-svg { width: 100%; height: 100%; }

  .chart-full { background: var(--card); border: 1px solid var(--card-border); border-radius: 14px; padding: 18px; margin-bottom: 24px; }
  .chart-full h3 { font-size: 0.75rem; font-weight: 600; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 14px; }
  .chart-full .chart-container { height: 180px; }

  /* Transfers */
  .transfers-section { background: var(--card); border: 1px solid var(--card-border); border-radius: 14px; padding: 18px; margin-bottom: 24px; }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .section-header h3 { font-size: 0.75rem; font-weight: 600; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; }
  .transfer-count { font-size: 0.7rem; color: var(--blue-light); background: rgba(59,130,246,0.1); padding: 2px 10px; border-radius: 10px; }

  .transfer-item {
    display: grid; grid-template-columns: 1fr 140px 50px 90px 80px;
    align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px;
    margin-bottom: 4px; transition: background 0.15s;
  }
  .transfer-item:hover { background: rgba(255,255,255,0.02); }
  .transfer-item .fname { font-size: 0.78rem; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .mini-bar { height: 6px; background: var(--mini-bar-bg); border-radius: 3px; overflow: hidden; }
  .mini-fill { height: 100%; background: var(--blue); border-radius: 3px; transition: width 2s ease; }
  .transfer-item .tpct { font-size: 0.75rem; font-weight: 600; color: var(--blue-light); text-align: right; }
  .transfer-item .tspeed { font-size: 0.7rem; color: var(--text-dim); text-align: right; }
  .transfer-item .teta { font-size: 0.7rem; color: var(--text-dim); text-align: right; }

  /* Recent + Types */
  .recent-section { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 700px) {
    .recent-section { grid-template-columns: 1fr; }
    .transfer-item { grid-template-columns: 1fr 80px 40px 60px; gap: 6px; padding: 8px 6px; }
    .transfer-item .teta { display: none; }
    .transfer-item .fname { font-size: 0.7rem; }
    body { padding: 12px 10px; }
    .header { flex-direction: column; gap: 10px; align-items: flex-start; }
    .header-left { flex-wrap: wrap; gap: 8px; }
    .header-right { text-align: left; }
    .big-pct { font-size: 2.2rem; }
    .big-bars { flex-direction: column; }
    .big-progress { padding: 16px; }
    .stat-value { font-size: 1.1rem; }
  }
  .recent-card { background: var(--card); border: 1px solid var(--card-border); border-radius: 14px; padding: 18px; overflow: hidden; min-width: 0; }
  .recent-card h3 { font-size: 0.75rem; font-weight: 600; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 12px; }
  .recent-file { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--card-border); }
  .recent-file:last-child { border-bottom: none; }
  .recent-file .rf-name { font-size: 0.73rem; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; margin-right: 12px; }
  .recent-file .rf-time { font-size: 0.65rem; color: var(--text-dim); white-space: nowrap; }
  .recent-file .rf-ext { font-size: 0.6rem; padding: 1px 6px; border-radius: 4px; margin-left: 8px; white-space: nowrap; }

  .types-grid { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .type-badge { display: flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; background: rgba(255,255,255,0.03); font-size: 0.7rem; }
  .type-badge .type-name { color: var(--text); }
  .type-badge .type-count { color: var(--text-dim); }
  .type-bar { height: 4px; border-radius: 2px; min-width: 12px; max-width: 80px; }

  /* Error */
  .error-section { background: rgba(239,68,68,0.05); border: 1px solid rgba(239,68,68,0.15); border-radius: 14px; padding: 16px 18px; margin-bottom: 24px; display: none; }
  .error-section.show { display: block; }
  .error-section h3 { font-size: 0.75rem; font-weight: 600; color: var(--red); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }
  .error-item { font-size: 0.75rem; color: var(--red); padding: 4px 0; font-family: 'SF Mono', 'Fira Code', monospace; }

  .footer { text-align: center; font-size: 0.65rem; color: var(--text-muted); padding: 12px 0; border-top: 1px solid var(--card-border); }

  /* Control buttons */
  .ctrl-btn {
    padding: 6px 18px; border: none; border-radius: 8px; font-size: 0.75rem;
    font-weight: 600; cursor: pointer; transition: all 0.2s; letter-spacing: 0.03em;
    text-transform: uppercase; min-height: 44px;
  }
  .ctrl-btn:active { transform: scale(0.95); }
  .ctrl-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .ctrl-btn.pause {
    background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid rgba(239,68,68,0.3);
  }
  .ctrl-btn.pause:hover:not(:disabled) { background: rgba(239,68,68,0.25); }
  .ctrl-btn.resume {
    background: rgba(34,197,94,0.15); color: var(--green); border: 1px solid rgba(34,197,94,0.3);
  }
  .ctrl-btn.resume:hover:not(:disabled) { background: rgba(34,197,94,0.25); }
  .ctrl-btn .spinner {
    display: inline-block; width: 10px; height: 10px; border: 2px solid currentColor;
    border-top-color: transparent; border-radius: 50%; animation: spin 0.6s linear infinite;
    margin-right: 6px; vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Toast notification */
  .toast {
    position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
    background: var(--card); border: 1px solid var(--card-border); border-radius: 10px;
    padding: 10px 20px; font-size: 0.8rem; color: var(--text); z-index: 200;
    opacity: 0; transition: opacity 0.3s; pointer-events: none;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
  }
  .toast.show { opacity: 1; }
</style>
</head>
<body>
<div class="container">

<div class="header">
  <div class="header-left">
    <h1 id="transferTitle">CloudMirror</h1>
    <div class="status-badge paused" id="statusBadge">
      <div class="status-dot" style="animation:none;background:var(--text-dim)"></div>
      <span id="statusText">Loading...</span>
    </div>
    <div class="session-badge" id="sessionBadge">Session 1</div>
    <button class="ctrl-btn pause" id="btnPause" onclick="doAction('pause')">Pause</button>
    <button class="ctrl-btn resume" id="btnResume" onclick="doAction('resume')" style="display:none">Resume</button>
    <a href="/wizard" class="ctrl-btn" style="background:rgba(167,139,250,0.15);color:var(--purple);border:1px solid rgba(167,139,250,0.3);text-decoration:none;padding:6px 18px;font-size:0.75rem;">New Transfer</a>
  </div>
  <div class="header-right" style="display:flex;align-items:center;gap:12px;">
    <div>
      <div>Wall time: <span id="wallClock" style="color:var(--text)">--</span></div>
      <div>Uptime: <span id="uptimePct" style="color:var(--green)">--</span></div>
      <div>Updated: <span id="lastUpdate">--</span></div>
    </div>
    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" title="Toggle dark/light mode">&#9790;</button>
  </div>
</div>

<!-- Empty state overlay -->
<div id="emptyState" style="display:none;text-align:center;padding:80px 20px;">
  <div style="font-size:4rem;margin-bottom:16px;opacity:0.5;">☁️</div>
  <div style="font-size:1.3rem;font-weight:700;color:var(--text);margin-bottom:8px;">No active transfer</div>
  <div style="font-size:0.9rem;color:var(--text-dim);margin-bottom:24px;">Set up a new transfer to start copying files between cloud services.</div>
  <a href="/wizard" style="display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:14px 32px;border-radius:12px;font-size:1rem;font-weight:600;background:linear-gradient(135deg,#1d4ed8,var(--blue));color:#fff;text-decoration:none;box-shadow:0 4px 14px rgba(59,130,246,0.3);">Start New Transfer</a>
</div>

<!-- Big progress -->
<div class="big-progress" id="dashboardContent">
  <div class="big-progress-header">
    <div class="big-pct"><span id="bigPct">0</span><span class="unit">%</span></div>
    <div class="big-detail">
      <div><span id="bpTransferred">--</span> / <span id="bpTotal">--</span></div>
      <div style="margin-top:4px;">ETA: <span id="bpEta" style="color:var(--orange);font-weight:600;">--</span></div>
      <div style="font-size:0.7rem;color:var(--text-dim);margin-top:2px;" id="finishTime"></div>
      <div class="session-note" id="sessionNote"></div>
    </div>
  </div>
  <div class="big-track">
    <div class="prev-fill" id="prevBar" style="width:0%"></div>
    <div class="big-fill" id="bigBar" style="width:0%"></div>
  </div>
  <div class="big-bars">
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

<!-- Stats -->
<div class="stats-grid" id="statsGrid">
  <div class="stat-card">
    <div class="stat-label">Current Speed</div>
    <div class="stat-value green" id="speed">--</div>
    <div class="stat-sub" id="speedSub">--</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Avg Speed (overall)</div>
    <div class="stat-value blue" id="avgSpeed">--</div>
    <div class="stat-sub" id="avgSpeedSub">across all sessions</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Peak Speed</div>
    <div class="stat-value purple" id="peakSpeed">--</div>
    <div class="stat-sub" id="peakTime">--</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Active Time</div>
    <div class="stat-value cyan" id="elapsed">--</div>
    <div class="stat-sub" id="elapsedSub">this session: --</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Files/min</div>
    <div class="stat-value orange" id="filesRate">--</div>
    <div class="stat-sub" id="filesRateSub">--</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Files Copied</div>
    <div class="stat-value yellow" id="totalCopied">--</div>
    <div class="stat-sub" id="totalCopiedSub">all sessions</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Total Downtime</div>
    <div class="stat-value pink" id="downtime">--</div>
    <div class="stat-sub" id="downtimeSub">--</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Errors</div>
    <div class="stat-value" id="errors" style="color:var(--green)">0</div>
    <div class="stat-sub" id="errorSub">none</div>
  </div>
</div>

<!-- Session Timeline -->
<div class="timeline-section" id="timelineSection" style="display:none">
  <h3 style="cursor:pointer;user-select:none;" onclick="toggleTimeline()">Session Timeline <span id="tlToggle" style="font-size:0.65rem;color:var(--text-muted);margin-left:6px;">&#9660;</span></h3>
  <div class="timeline" id="timeline"></div>
</div>

<!-- Charts -->
<div class="charts-row" id="chartsRow">
  <div class="chart-card">
    <h3>Transfer Speed</h3>
    <div class="chart-container"><svg class="chart-svg" id="speedChart"></svg></div>
  </div>
  <div class="chart-card">
    <h3>Data Progress Over Time</h3>
    <div class="chart-container"><svg class="chart-svg" id="progressChart"></svg></div>
  </div>
</div>

<div class="chart-full" id="chartsFullRow">
  <h3>Files Transferred Over Time (Global)</h3>
  <div class="chart-container"><svg class="chart-svg" id="filesChart"></svg></div>
</div>

<!-- Daily Transfer Bar Chart -->
<div class="chart-card" style="margin-bottom:24px;display:none;" id="dailyChartSection">
  <h3>Daily Transfer Volume</h3>
  <div id="dailyBars" style="display:flex;align-items:flex-end;gap:8px;height:120px;padding-top:12px;"></div>
</div>

<!-- Errors -->
<div class="error-section" id="errorSection">
  <h3>Errors</h3>
  <div id="errorList"></div>
</div>

<!-- Active Transfers -->
<div class="transfers-section" id="transfersSection">
  <div class="section-header">
    <h3>Active Transfers</h3>
    <div class="transfer-count" id="transferCount">0 active</div>
  </div>
  <div id="transfersList"></div>
</div>

<!-- Recent + Types -->
<div class="recent-section" id="recentSection">
  <div class="recent-card">
    <h3>Recently Completed</h3>
    <div id="recentFiles"></div>
  </div>
  <div class="recent-card">
    <h3>File Types (All Sessions)</h3>
    <div id="fileTypes"></div>
  </div>
</div>

<div class="footer" id="footer">
  CloudMirror Dashboard &middot; Auto-refresh 5s &middot; <span id="footerInfo">--</span>
</div>

</div>

<div class="toast" id="toast"></div>

<script>
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

let speedHistory = [];
let progressHistory = [];
let filesHistory = [];
let historyLoaded = false;
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
  // Skip redraw if data unchanged
  const dataKey = svgId + JSON.stringify(data.slice(-5));
  if (drawAreaChart._cache && drawAreaChart._cache[svgId] === dataKey) return;
  if (!drawAreaChart._cache) drawAreaChart._cache = {};
  drawAreaChart._cache[svgId] = dataKey;

  const svg = document.getElementById(svgId);
  if (!svg) return;
  const cs = getComputedStyle(document.documentElement);
  const cGrid = cs.getPropertyValue('--chart-grid').trim() || '#151d35';
  const cText = cs.getPropertyValue('--chart-text').trim() || '#2a3555';
  const w = svg.clientWidth || 500;
  const h = svg.clientHeight || 140;
  const realData = data.filter(v => v !== null);
  if (realData.length < 2) {
    const emptyColor = cs.getPropertyValue('--text-dim').trim() || '#6b7280';
    svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="${emptyColor}" font-size="12" font-family="Inter">Collecting data...</text>`;
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
    html += `<text x="${pad.l - 6}" y="${y + 3}" text-anchor="end" fill="${cText}" font-size="9" font-family="Inter">${formatY ? formatY(tick) : tick.toFixed(1)}</text>`;
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
    html += `<circle cx="${lx}" cy="${ly}" r="3.5" fill="${color}" stroke="${cs.getPropertyValue('--card').trim()}" stroke-width="2"/>`;
    html += `<text x="${w-pad.r}" y="${h-3}" text-anchor="end" fill="${cText}" font-size="9" font-family="Inter">${formatY ? formatY(last.v) : last.v.toFixed(2)}</text>`;
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

async function refresh() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const d = await res.json();

    // Show empty state if API returns error (no log file) AND rclone is NOT running
    if (d.error && !d.rclone_running) {
      document.getElementById('emptyState').style.display = 'block';
      ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
      });
      return;
    }
    // If rclone is running but log not ready yet, show Starting state
    if (d.error && d.rclone_running) {
      document.getElementById('emptyState').style.display = 'none';
      ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
      });
      const badge = document.getElementById('statusBadge');
      badge.className = 'status-badge active';
      document.getElementById('statusText').textContent = 'Starting...';
      badge.querySelector('.status-dot').style.animation = '';
      return;
    }

    // Status badge
    const badge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    if (d.finished && d.global_pct >= 100) {
      badge.className = 'status-badge active';
      statusText.textContent = 'Complete';
      badge.querySelector('.status-dot').style.animation = 'none';
      badge.querySelector('.status-dot').style.background = 'var(--green)';
      updateButtons(false);
      if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = setInterval(refresh, 30000); }
    } else if (d.rclone_running && !d.speed && !d.session_num) {
      badge.className = 'status-badge active';
      statusText.textContent = 'Starting...';
      badge.querySelector('.status-dot').style.animation = '';
      updateButtons(true);
    } else if (d.finished) {
      badge.className = 'status-badge paused';
      statusText.textContent = 'Paused';
      badge.querySelector('.status-dot').style.animation = 'none';
      updateButtons(false);
    } else if (!d.speed && !d.session_num) {
      badge.className = 'status-badge paused';
      statusText.textContent = 'Idle';
      badge.querySelector('.status-dot').style.animation = 'none';
      badge.querySelector('.status-dot').style.background = 'var(--text-dim)';
      updateButtons(false);
    } else {
      badge.className = 'status-badge active';
      statusText.textContent = 'Transferring';
      badge.querySelector('.status-dot').style.animation = '';
      updateButtons(true);
    }

    // Empty state: show when truly no transfer (not running, no data)
    const isEmpty = !d.rclone_running && !d.session_num && (d.global_total_bytes === undefined || d.global_total_bytes === 0) && !d.speed;
    document.getElementById('emptyState').style.display = isEmpty ? 'block' : 'none';
    ['dashboardContent','statsGrid','timelineSection','chartsRow','chartsFullRow','transfersSection','recentSection','footer'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = isEmpty ? 'none' : '';
    });
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
    if (d.uptime_pct !== undefined) document.getElementById('uptimePct').textContent = d.uptime_pct + '%';

    // Big progress - GLOBAL
    const pct = d.global_pct || 0;
    document.getElementById('bigPct').textContent = pct;
    document.getElementById('bigBar').style.width = Math.max(pct, 0.2) + '%';
    if (d.global_transferred) document.getElementById('bpTransferred').textContent = d.global_transferred;
    if (d.global_total) document.getElementById('bpTotal').textContent = d.global_total;
    if (d.eta) {
      document.getElementById('bpEta').textContent = fmtEta(d.eta);
      const etaStr = d.eta;
      let etaSec = 0;
      const ed = etaStr.match(/(\d+)d/); if (ed) etaSec += parseInt(ed[1]) * 86400;
      const eh = etaStr.match(/(\d+)h/); if (eh) etaSec += parseInt(eh[1]) * 3600;
      const em = etaStr.match(/(\d+)m/); if (em) etaSec += parseInt(em[1]) * 60;
      const es = etaStr.match(/([\d.]+)s/); if (es) etaSec += parseFloat(es[1]);
      if (etaSec > 0 && etaSec < 604800) {
        const finish = new Date(Date.now() + etaSec * 1000);
        const opts = { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' };
        document.getElementById('finishTime').textContent = 'Finish: ' + finish.toLocaleDateString('ro-RO', opts);
      } else {
        document.getElementById('finishTime').textContent = '';
      }
    }

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
      document.getElementById('speed').textContent = fmtSpeed(speedMbs);
      const realSpeeds = speedHistory.filter(v => v !== null);
      if (realSpeeds.length >= 2) {
        const prev = realSpeeds[realSpeeds.length - 2];
        const diff = speedMbs - prev;
        const arrow = diff > 0.05 ? '\u2191' : diff < -0.05 ? '\u2193' : '\u2192';
        const diffColor = diff > 0 ? 'var(--green)' : diff < 0 ? 'var(--red)' : 'var(--text-dim)';
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
      document.getElementById('avgSpeedSub').textContent = `across ${d.session_num || 1} session(s)`;
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
      document.getElementById('errorList').innerHTML = d.error_messages.map(e => `<div class="error-item">${esc(e)}</div>`).join('');
    } else {
      document.getElementById('errorSection').classList.remove('show');
    }

    // Session timeline
    if (d.sessions && d.sessions.length > 0) {
      const ts = document.getElementById('timelineSection');
      ts.style.display = 'block';
      let html = '';
      d.sessions.forEach((s, idx) => {
        const isLast = idx === d.sessions.length - 1;
        const dotClass = isLast ? (d.finished ? 'done' : 'active') : 'done';
        const label = isLast && !d.finished ? 'Current Session' : `Session ${s.num}`;
        html += `<div class="tl-item">
          <div class="tl-dot ${dotClass}"></div>
          <div class="tl-header">
            <div class="tl-title">${label}</div>
            <div class="tl-time">${esc(s.start || '--')} → ${isLast && !d.finished ? 'now' : esc(s.end || '--')}</div>
          </div>
          <div class="tl-stats">
            Transferred: <span>${esc(s.transferred)}</span> &middot;
            Files: <span>${s.files.toLocaleString()}</span> &middot;
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
        let statusHtml = t.speed || '--';
        let barColor = 'var(--blue)';
        if (isStalled) {
          statusHtml = '<span style="color:var(--orange);font-size:0.65rem;font-weight:600">STALLED</span>';
          barColor = 'var(--orange)';
        } else if (isQueued) {
          statusHtml = '<span style="color:var(--text-muted);font-size:0.65rem;font-weight:600">QUEUED</span>';
          barColor = 'var(--text-muted)';
        }
        return `<div class="transfer-item">
          <div class="fname" title="${esc(t.name)}">${esc(t.name)}${t.size ? ' <span style="color:var(--text-dim);font-size:0.65rem">(' + esc(t.size) + ')</span>' : ''}</div>
          <div class="mini-bar"><div class="mini-fill" style="width:${t.pct}%;background:${barColor}"></div></div>
          <div class="tpct">${t.pct}%</div>
          <div class="tspeed">${statusHtml}</div>
          <div class="teta">${eta}</div>
        </div>`;
      }).join('');
    } else {
      list.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-dim);font-size:0.8rem;">No active transfers</div>';
    }

    // Recent files
    if (d.recent_files && d.recent_files.length > 0) {
      document.getElementById('recentFiles').innerHTML = d.recent_files.map(f => {
        const ext = getExtension(f.name);
        return `<div class="recent-file">
          <div class="rf-name" title="${esc(f.name)}">${esc(f.name)}</div>
          <span class="rf-ext" style="background:${getTypeColor(ext)}22;color:${getTypeColor(ext)}">${ext}</span>
          <div class="rf-time">${f.time}</div>
        </div>`;
      }).join('');
    } else {
      document.getElementById('recentFiles').innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-dim);font-size:0.8rem;">No recent completions</div>';
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
            <span class="type-name">.${ext}</span>
            <span class="type-count">${count}</span>
          </div>`;
        }).join('') + '</div>';
    }

    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();

    updateFavicon(pct);

    document.title = `${pct}% - CloudMirror`;
    // Daily transfer bar chart
    if (d.daily_stats && d.daily_stats.length > 0) {
      document.getElementById('dailyChartSection').style.display = '';
      const maxGib = Math.max(...d.daily_stats.map(x => x.gib));
      const container = document.getElementById('dailyBars');
      container.innerHTML = d.daily_stats.map(ds => {
        const h = maxGib > 0 ? Math.max(4, (ds.gib / maxGib) * 100) : 4;
        const dayLabel = ds.day.slice(5);
        const isToday = ds.day === new Date().toISOString().slice(0,10).replace(/\//g,'-');
        const color = isToday ? 'var(--green)' : 'var(--blue)';
        return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <span style="font-size:0.65rem;color:var(--text)">${esc(ds.gib + ' GiB')}</span>
          <div style="width:100%;height:${h}px;background:${color};border-radius:4px 4px 0 0;opacity:0.7;"></div>
          <span style="font-size:0.6rem;color:var(--text-dim)">${esc(dayLabel)}</span>
        </div>`;
      }).join('');
    }

    if (d.listed) document.getElementById('footerInfo').textContent = `Listed: ${d.listed.toLocaleString()} objects`;

    checkNotifications(d);

  } catch(e) { console.error('Refresh error:', e); }
}

// ─── Pause / Resume ───────────────────────────────────────────────────────
function showToast(msg, color) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderColor = color || 'var(--blue)';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
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
    const res = await fetch(`/api/${action}`, { method: 'POST' });
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
  if (isRunning) {
    btnPause.style.display = '';
    btnResume.style.display = 'none';
  } else {
    btnPause.style.display = 'none';
    btnResume.style.display = '';
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
  document.getElementById('themeToggle').textContent = next === 'light' ? '\u2600' : '\u263E';
  // Redraw charts with new colors
  drawAreaChart('speedChart', speedHistory, '#22c55e', 'speedGrad', v => fmtSpeed(v), true);
  drawAreaChart('progressChart', progressHistory, '#3b82f6', 'progGrad', v => v.toFixed(0) + '%', true, 100);
  drawAreaChart('filesChart', filesHistory, '#a78bfa', 'filesGrad', v => Math.round(v).toLocaleString(), true);
}
// Load saved theme
(function() {
  const saved = localStorage.getItem('cloudmirror-theme');
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.getElementById('themeToggle').textContent = '\u2600';
  }
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
  ctx.strokeStyle = '#3b82f6';
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
let prevErrors = 0;
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

refresh();
let refreshInterval = setInterval(refresh, 5000);
window.addEventListener('resize', () => {
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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudMirror Setup</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { scrollbar-width: none; }
  :root {
    --bg: #060a14; --card: #0d1220; --card-border: #151d35;
    --text: #c8d3e8; --text-dim: #7a8baa; --text-muted: #5a6a8a;
    --blue: #3b82f6; --blue-light: #60a5fa; --green: #22c55e;
    --orange: #f59e0b; --red: #ef4444; --purple: #a78bfa;
    --cyan: #22d3ee; --pink: #f472b6; --card-hover: #131b30;
  }
  [data-theme="light"] {
    --bg: #f0f2f5; --card: #ffffff; --card-border: #e2e8f0;
    --text: #1e293b; --text-dim: #64748b; --text-muted: #94a3b8;
    --blue: #2563eb; --blue-light: #3b82f6; --green: #16a34a;
    --orange: #d97706; --red: #dc2626; --purple: #7c3aed;
    --cyan: #0891b2; --pink: #db2777; --card-hover: #f8fafc;
  }
  [data-theme="light"] .wizard-title { color: #0f172a; }
  [data-theme="light"] .provider-card:hover { border-color: var(--blue); background: #f0f7ff; }
  [data-theme="light"] .provider-card.selected { background: #eff6ff; }

  html, body { overflow-x: hidden; }
  body::-webkit-scrollbar { width: 0; background: transparent; }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg); color: var(--text);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 20px;
  }

  .wizard-container {
    max-width: 700px; width: 100%; position: relative;
  }

  /* Theme toggle */
  .theme-toggle {
    position: fixed; top: 20px; right: 20px;
    background: var(--card); border: 1px solid var(--card-border); border-radius: 8px;
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
    background: var(--card-border); transition: all 0.3s;
  }
  .dot.active { background: var(--blue); transform: scale(1.2); }
  .dot.done { background: var(--green); }

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

  .provider-card {
    background: var(--card); border: 2px solid var(--card-border);
    border-radius: 14px; padding: 20px 16px; text-align: center;
    cursor: pointer; transition: all 0.2s; user-select: none;
  }
  .provider-card:hover { border-color: var(--blue); background: var(--card-hover); transform: translateY(-2px); }
  .provider-card.selected { border-color: var(--blue); background: rgba(59,130,246,0.08); }
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
    padding: 14px 32px; border-radius: 12px; font-size: 1rem; font-weight: 600;
    border: none; cursor: pointer; transition: all 0.2s; font-family: inherit;
  }
  .btn-primary {
    background: linear-gradient(135deg, #1d4ed8, var(--blue)); color: #fff;
    box-shadow: 0 4px 14px rgba(59,130,246,0.3);
  }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(59,130,246,0.4); }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; transform: none; box-shadow: none; }
  .btn-secondary {
    background: var(--card); color: var(--text-dim); border: 1px solid var(--card-border);
  }
  .btn-secondary:hover { border-color: var(--text-dim); color: var(--text); }
  .btn-big {
    width: 100%; padding: 18px; font-size: 1.1rem; border-radius: 14px;
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
    color: var(--text-dim); margin-bottom: 8px; text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .form-input {
    width: 100%; padding: 12px 16px; border-radius: 10px;
    background: var(--bg); border: 1px solid var(--card-border);
    color: var(--text); font-size: 1rem; font-family: inherit;
    transition: border-color 0.2s;
  }
  .form-input:focus { outline: none; border-color: var(--blue); }
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
  .speed-card.selected { border-color: var(--blue); background: rgba(59,130,246,0.06); }
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
<button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">☀️</button>

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
      <div class="welcome-logo">☁️</div>
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
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="16" font-weight="800" fill="#d9272e">MEGA</text></svg></div>
        <div class="provider-name">MEGA</div>
      </div>
      <div class="provider-card" data-provider="s3" data-name="Amazon S3" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="24" font-weight="800" fill="#ff9900">S3</text></svg></div>
        <div class="provider-name">Amazon S3</div>
      </div>
      <div class="provider-card" data-provider="protondrive" data-name="Proton Drive" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><path d="M20 3L6 10v10c0 9.5 5.9 18.4 14 20 8.1-1.6 14-10.5 14-20V10L20 3z" fill="#6d4aff"/></svg></div>
        <div class="provider-name">Proton Drive</div>
      </div>
      <div class="provider-card" data-provider="local" data-name="Local Folder" tabindex="0" role="button" onclick="selectSource(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectSource(this)}">
        <div class="provider-icon"><svg width="40" height="40" viewBox="0 0 40 40"><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" font-size="24">&#x1F4BB;</text></svg></div>
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
        <div class="form-hint">The folder on your computer where your files are stored.</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;">
          <button type="button" class="btn-secondary" style="padding:6px 12px;font-size:0.7rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);" onclick="document.getElementById('sourcePathInput').value=((window._homeDir||'/tmp')+'/Desktop');document.getElementById('sourcePathInput').dispatchEvent(new Event('input'))">Desktop</button>
          <button type="button" class="btn-secondary" style="padding:6px 12px;font-size:0.7rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);" onclick="document.getElementById('sourcePathInput').value=((window._homeDir||'/tmp')+'/Documents');document.getElementById('sourcePathInput').dispatchEvent(new Event('input'))">Documents</button>
          <button type="button" class="btn-secondary" style="padding:6px 12px;font-size:0.7rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);" onclick="document.getElementById('sourcePathInput').value=((window._homeDir||'/tmp')+'/Downloads');document.getElementById('sourcePathInput').dispatchEvent(new Event('input'))">Downloads</button>
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
        <div class="form-hint">Where to save the copied files on your computer.</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;">
          <button type="button" style="padding:6px 12px;font-size:0.7rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);" onclick="document.getElementById('destPathInput').value=((window._homeDir||'/tmp')+'/Desktop/CloudMirror-Backup');document.getElementById('destPathInput').dispatchEvent(new Event('input'))">Desktop/CloudMirror-Backup</button>
          <button type="button" style="padding:6px 12px;font-size:0.7rem;border-radius:8px;cursor:pointer;border:1px solid var(--card-border);background:var(--card);color:var(--text-dim);" onclick="document.getElementById('destPathInput').value=((window._homeDir||'/tmp')+'/Documents/CloudMirror-Backup');document.getElementById('destPathInput').dispatchEvent(new Event('input'))">Documents/CloudMirror-Backup</button>
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
        <div class="speed-options">
          <div class="speed-card" onclick="selectSpeed(this, '4')">
            <input type="radio" name="speed" value="4">
            <div class="speed-label">Normal</div>
            <div class="speed-desc">4 files at a time</div>
          </div>
          <div class="speed-card selected" onclick="selectSpeed(this, '8')">
            <input type="radio" name="speed" value="8" checked>
            <div class="speed-label">Fast</div>
            <div class="speed-desc">8 files at a time</div>
          </div>
          <div class="speed-card" onclick="selectSpeed(this, '16')">
            <input type="radio" name="speed" value="16">
            <div class="speed-label">Maximum</div>
            <div class="speed-desc">16 files at a time</div>
          </div>
        </div>
      </div>
      <div class="form-group" style="margin-bottom:0;">
        <label class="form-label" for="excludePatterns">Exclude Patterns (optional)</label>
        <input class="form-input" id="excludePatterns" type="text" placeholder="Trash, .Trash, Personal Vault">
        <div class="form-hint">Comma-separated folder names to skip</div>
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
    <div style="font-size:0.8rem;color:var(--text-dim);margin-bottom:16px;text-align:center;">
      When you click Connect, a browser tab will open for authentication.<br>
      Sign in to authorize CloudMirror, then return here.
    </div>
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
      <button class="btn btn-primary btn-big" id="startBtn" onclick="startTransfer()">
        Start Transfer
      </button>
      <button class="btn btn-secondary" onclick="goTo(5)" style="align-self:flex-start;">Back</button>
    </div>
  </div>
</div>

<script>
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
  document.querySelector('.theme-toggle').textContent = next === 'light' ? '🌙' : '☀️';
  localStorage.setItem('cloudmirror-theme', next);
}
(function() {
  const saved = localStorage.getItem('cloudmirror-theme');
  if (saved === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('.theme-toggle').textContent = '🌙';
  }
})();

// Navigation
function goTo(step) {
  if (step >= 3 && !sourceProvider) return;
  if (step >= 4 && !destProvider) return;
  if (step === 3) updateDestGrid();
  if (step === 5) buildConnectStep();
  if (step === 6) {
    if (sourceProvider === destProvider && sourceProvider !== 'local') {
      if (!confirm('Source and destination are the same service. This will copy between different accounts. Continue?')) {
        return;
      }
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
}

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
    input.addEventListener('input', () => {
      document.getElementById('sourceNext').disabled = !input.value.trim();
    });
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

  document.getElementById('destLocalPath').classList.toggle('show', destProvider === 'local');
  document.getElementById('destOtherName').classList.toggle('show', destProvider === 'other');
  // For Other provider, only enable Next when name is entered
  if (destProvider === 'other') {
    const input = document.getElementById('destOtherInput');
    document.getElementById('destNext').disabled = !input.value.trim();
    input.addEventListener('input', () => {
      document.getElementById('destNext').disabled = !input.value.trim();
    });
  } else {
    document.getElementById('destNext').disabled = false;
  }
}

function updateDestGrid() {
  document.querySelectorAll('#destGrid .provider-card').forEach(c => {
    if (c.dataset.provider === sourceProvider && sourceProvider !== 'local' && sourceProvider !== 'other') {
      c.classList.add('disabled');
    } else {
      c.classList.remove('disabled');
    }
  });
}

function selectSpeed(card, val) {
  document.querySelectorAll('.speed-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  selectedSpeed = val;
}

// Build connect step
async function buildConnectStep() {
  const list = document.getElementById('connectList');
  list.innerHTML = '';

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
      const installResp = await fetch('/api/wizard/check-rclone', {method:'POST'});
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
    if (destProvider !== sourceProvider) {
      items.push({provider: destProvider, name: destName, display: destDisplayName, role: 'dest'});
    }
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
      headers: {'Content-Type': 'application/json'},
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
        headers: {'Content-Type': 'application/json'},
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
  const speedLabels = {'4': 'Normal (4 files)', '8': 'Fast (8 files)', '16': 'Maximum (16 files)'};

  let srcPath = getSourcePath();
  let dstPath = getDestPath();

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
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
  `;
}

function getSourcePath() {
  const srcSub = document.getElementById('sourceSubfolder').value.trim();
  if (sourceProvider === 'local') {
    const p = document.getElementById('sourcePathInput').value.trim();
    if (!p) { alert('Please enter a folder path.'); return null; }
    return p;
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
    if (!p) { alert('Please enter a folder path.'); return null; }
    return p;
  }
  if (destProvider === 'other') {
    const n = document.getElementById('destOtherInput').value.trim();
    return n + ':' + (dstSub || '');
  }
  return destName + ':' + (dstSub || '');
}

async function startTransfer() {
  const btn = document.getElementById('startBtn');
  if (btn.disabled) return;
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Starting transfer...';

  const safetyTimeout = setTimeout(() => {
    btn.disabled = false;
    btn.textContent = 'Start Transfer';
    alert('Transfer may have started. Check the dashboard.');
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
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        source: src,
        dest: dst,
        transfers: selectedSpeed,
        excludes: excludeList,
        source_type: sourceProvider,
        dest_type: destProvider
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
      alert('Error: ' + (data.msg || 'Failed to start transfer'));
    }
  } catch(e) {
    clearTimeout(safetyTimeout);
    btn.disabled = false;
    btn.textContent = 'Start Transfer';
    alert('Error starting transfer. Check the console.');
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
        cmd = [
            "rclone", "config", "create", name, provider_type,
            f"user={username}", f"pass={obscured}",
        ]
    elif provider_type == "protondrive":
        if not username or not password:
            return {"ok": False, "needs_credentials": True, "msg": "Proton Drive requires your Proton username and password.",
                    "user_label": "Username", "pass_label": "Password"}
        result = subprocess.run(["rclone", "obscure", password], capture_output=True, text=True)
        if result.returncode != 0:
            return {"ok": False, "msg": "Failed to process credentials"}
        obscured_pw = result.stdout.strip()
        cmd = [
            "rclone", "config", "create", name, provider_type,
            f"username={username}",
            f"password={obscured_pw}",
        ]
    elif provider_type == "s3":
        if not username or not password:
            return {"ok": False, "needs_credentials": True,
                    "msg": "Amazon S3 requires your Access Key ID and Secret Access Key.",
                    "user_label": "Access Key ID", "pass_label": "Secret Access Key"}
        cmd = [
            "rclone", "config", "create", name, provider_type,
            f"access_key_id={username}",
            f"secret_access_key={password}",
            "provider=AWS",
        ]
    else:
        # For OAuth-based providers, rclone config create will open browser automatically
        cmd = ["rclone", "config", "create", name, provider_type]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            # Validate the remote actually works
            if provider_type in ("mega", "protondrive"):
                check = subprocess.run(["rclone", "lsd", f"{name}:"], capture_output=True, text=True, timeout=30)
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
        self.end_headers()
        self.wfile.write(html.encode())

    def _read_body(self):
        # Cap request size to prevent memory exhaustion from oversized payloads.
        length = int(self.headers.get("Content-Length", 0))
        if length > 10240:  # 10KB limit
            return None
        if length > 0:
            try:
                return json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, ValueError):
                return None
        return {}

    def do_GET(self):
        global TRANSFER_ACTIVE
        if self.path == "/api/status":
            self._send_json(parse_current())
        elif self.path == "/api/wizard/status":
            self._send_json({
                "rclone_installed": find_rclone() is not None,
                "remotes": get_existing_remotes(),
                "home_dir": os.path.expanduser("~"),
            })
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
                        subprocess.run(["brew", "install", "rclone"], capture_output=True, timeout=120)
                    elif system in ("darwin", "linux"):
                        subprocess.run(
                            ["bash", "-c", "curl -s https://rclone.org/install.sh | sudo bash"],
                            capture_output=True, timeout=120
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
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
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
    global RCLONE_CMD, TRANSFER_ACTIVE

    if TRANSFER_ACTIVE or is_rclone_running():
        return {"ok": False, "msg": "A transfer is already running"}

    source = body.get("source", "")
    dest = body.get("dest", "")
    try:
        transfers = int(body.get("transfers", "8"))
        if not (1 <= transfers <= 64):
            transfers = 8
    except (ValueError, TypeError):
        transfers = 8
    excludes = body.get("excludes", [])
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
        if not validate_rclone_input(excl, "exclude"):
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
        "--stats=30s",
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

    # S6: Save RCLONE_CMD to state but strip credential flags
    safe_cmd = [arg for arg in RCLONE_CMD if not any(secret in arg.lower() for secret in ['password', 'pass', 'user', 'token', 'key=', 'secret'])]
    with state_lock:
        state["rclone_cmd"] = safe_cmd
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
    global state, TRANSFER_ACTIVE, RCLONE_CMD, rclone_pid

    # Load RCLONE_CMD from state if not set (enables resume after restart)
    with state_lock:
        if not RCLONE_CMD and "rclone_cmd" in state:
            RCLONE_CMD = state["rclone_cmd"]

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

    # Try to open browser automatically
    try:
        webbrowser.open(f"http://localhost:{PORT}")
    except Exception:
        pass

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as e:
        if "Address already in use" in str(e) or e.errno == 48:
            print(f"\n  Error: Port {PORT} is already in use.")
            print(f"  Either stop the other process or set a different port:")
            print(f"  Open the file and change PORT = {PORT} to another value.\n")
            sys.exit(1)
        raise
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
        "--stats=30s",
        "--stats-log-level=INFO",
    ] + extra_flags

    # Add default transfers if not specified
    if not any(f.startswith("--transfers") for f in extra_flags):
        RCLONE_CMD.append("--transfers=8")
    if not any(f.startswith("--checkers") for f in extra_flags):
        RCLONE_CMD.append("--checkers=16")


if __name__ == "__main__":
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
