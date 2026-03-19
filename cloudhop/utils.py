"""CloudHop utilities - pure functions and constants."""

import os
import re
from typing import List, Optional

# ─── Constants ────────────────────────────────────────────────────────────────

PORT: int = 8787
TRANSFER_LABEL: str = "Source -> Destination"

_CM_DIR: str = os.path.join(os.path.expanduser("~"), ".cloudhop")
os.makedirs(_CM_DIR, mode=0o700, exist_ok=True)
LOG_TAIL_BYTES: int = 16000
RECENT_FILES_INITIAL_CHUNK: int = 100000
RECENT_FILES_MAX_CHUNK: int = 2000000
ERROR_TAIL_BYTES: int = 100000
CHART_DOWNSAMPLE_TARGET: int = 200
SCANNER_INTERVAL_SEC: int = 30
MIN_SESSION_ELAPSED_SEC: int = 300
MAX_REQUEST_BODY_BYTES: int = 10240
MIN_DOWNTIME_GAP_SEC: int = 60
RCLONE_SIZE_TIMEOUT_SEC: int = 600
RCLONE_CONFIG_TIMEOUT_SEC: int = 120
RCLONE_CHECK_TIMEOUT_SEC: int = 30
RCLONE_PREVIEW_TIMEOUT_SEC: int = 60
RCLONE_INSTALL_TIMEOUT_SEC: int = 120
MAX_TRANSFERS: int = 64
MAX_HISTORY_ENTRIES: int = 50000

# ─── Compiled regexes ────────────────────────────────────────────────────────

RE_TRANSFERRED_BYTES = re.compile(
    r"Transferred:\s+([\d.]+\s+\S+)\s*/\s*([\d.]+\s+\S+),\s*(\d+)%,\s*([\d.]+\s*\S+/s)"
)
RE_TRANSFERRED_FILES = re.compile(
    r"Transferred:\s+(\d+)\s*/\s*(\d+),\s*(\d+)%"
)
RE_ELAPSED = re.compile(r"Elapsed time:\s*(.+)")
RE_ERRORS = re.compile(r"Errors:\s+(\d+)")
RE_SPEED = re.compile(r"([\d.]+)\s*([KMGT]i?B)/s", re.I)
RE_COPIED = re.compile(r"INFO\s+:\s+(.+?):\s+Copied\s+\(new\)")
RE_ACTIVE = re.compile(
    r"\*\s+(.+?):\s+(\d+)%\s*/(\S+),\s*(\S+/s),\s*(\S+)"
)
RE_ACTIVE2 = re.compile(
    r"\*\s+(.+?):\s+(\d+)%\s*/(\S+),\s*(\S+/s)"
)
RE_ACTIVE3 = re.compile(r"\*\s+(.+?):\s+transferring")
RE_FULL_TRANSFER_ETA = re.compile(
    r"Transferred:\s+([\d.]+\s+\S+)\s*/\s*([\d.]+\s+\S+),\s*(\d+)%,\s*([\d.]+\s*\S+/s),\s*ETA\s*(\S+)"
)
RE_CHECKS_LISTED = re.compile(
    r"Checks:\s+(\d+)\s*/\s*(\d+).+Listed\s+(\d+)"
)
RE_COPIED_WITH_TS = re.compile(
    r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+INFO\s+:\s+(.+?):\s+Copied\s+\(new\)"
)
RE_ERROR_MSG = re.compile(r"\d{2}:\d{2}:\d{2}\s+ERROR\s+:\s+(.+)")
RE_TIMESTAMP = re.compile(
    r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"
)
RE_FILES_HIST = re.compile(
    r"Transferred:\s+(\d+)\s*/\s*\d+,\s*\d+%"
)
RE_SIZE_VALUE = re.compile(r"([\d.]+)\s*(\S+)")
RE_HOURS = re.compile(r"(\d+)h")
RE_MINUTES = re.compile(r"(\d+)m")
RE_SECONDS = re.compile(r"([\d.]+)s")


# ─── Pure utility functions ───────────────────────────────────────────────────


def validate_rclone_input(value: str, field_name: str) -> bool:
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


def validate_exclude_pattern(value: str) -> bool:
    """Stricter validation for exclude patterns - also rejects shell glob injection chars."""
    if not validate_rclone_input(value, "exclude"):
        return False
    if any(c in value for c in ('{', '}', '[', ']')):
        return False
    return True


def _sanitize_rclone_error(stderr: str) -> str:
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


def to_bytes(size_str: str) -> float:
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


def fmt_bytes(b: float) -> str:
    """Format bytes to human readable string."""
    if b >= 1024 ** 4:
        return f"{b / 1024**4:.2f} TiB"
    if b >= 1024 ** 3:
        return f"{b / 1024**3:.2f} GiB"
    if b >= 1024 ** 2:
        return f"{b / 1024**2:.2f} MiB"
    if b >= 1024:
        return f"{b / 1024:.2f} KiB"
    return f"{b:.0f} B"


def parse_elapsed(s: str) -> float:
    """Parse '14h59m30.0s' or '28m0.0s' to seconds."""
    sec = 0.0
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


def fmt_duration(sec: float) -> str:
    """Format seconds to 'Xd Xh Xm Xs'."""
    if sec <= 0:
        return "0s"
    d = int(sec // 86400)
    h = int((sec % 86400) // 3600)
    m = int((sec % 3600) // 60)
    s = int(sec % 60)
    parts: List[str] = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def downsample(arr: list, target: int = CHART_DOWNSAMPLE_TARGET) -> list:
    """Reduce a list to approximately ``target`` evenly-spaced samples."""
    if target <= 0 or len(arr) <= target:
        return arr
    step = len(arr) / target
    out: List = []
    for i in range(target):
        idx = int(i * step)
        out.append(arr[idx])
    if out and out[-1] != arr[-1]:
        out.append(arr[-1])
    return out


def get_remote_label(path: str) -> str:
    """Turn 'onedrive:' into 'OneDrive', 'gdrive:backup' into 'Google Drive/backup'."""
    labels = {
        "protondrive": "Proton Drive",
        "onedrive": "OneDrive",
        "gdrive": "Google Drive",
        "drive": "Google Drive",
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
    # First try exact match, then substring match (avoids "ftp" matching "sftp")
    for key, label in labels.items():
        if key == name:
            subfolder = path.split(":", 1)[1] if ":" in path else ""
            if subfolder:
                return f"{label}/{subfolder}"
            return label
    for key, label in labels.items():
        if key in name:
            # Add subfolder if present
            subfolder = path.split(":", 1)[1] if ":" in path else ""
            if subfolder:
                return f"{label}/{subfolder}"
            return label
    if ":" not in path or path.startswith("/") or path.startswith("./"):
        return "Local"
    remote_name = path.split(":")[0]
    return remote_name if remote_name else "Local"


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
