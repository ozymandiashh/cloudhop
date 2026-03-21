"""CloudHop transfer management.

What this module does
---------------------
Manages the rclone subprocess lifecycle, parses rclone's log output to track
progress, and persists session history across restarts.

Threading model
---------------
Three locks protect different scopes of mutable state:

- ``state_lock`` (RLock): guards ``self.state`` (the dict written to
  cloudhop_*_state.json), ``self.rclone_pid``, ``self._rclone_proc``, and
  ``self.transfer_active``.
  Re-entrant so that methods that already hold it can call helpers safely.

- ``transfer_lock`` (Lock): serialises pause / resume / start_transfer so only
  one of those operations runs at a time.  Prevents a resume racing a pause.

- ``_scan_lock`` (Lock): prevents concurrent calls to
  ``_scan_full_log_locked``.  The background scanner and an ad-hoc call from
  ``_pause_locked`` could otherwise both walk the log file simultaneously.

Lock ordering
-------------
Locks MUST be acquired in this order to prevent deadlocks::

    transfer_lock -> _scan_lock -> state_lock

Never acquire a lock that precedes a lock you already hold.  ``state_lock``
is an RLock so re-entrant acquisition within the same thread is safe.

Data flow
---------
1. rclone runs as a detached subprocess and writes structured log lines to a
   file (e.g. ``~/.cloudhop/cloudhop_<id>.log``).
2. ``background_scanner`` calls ``scan_full_log`` every 30 s.
   ``scan_full_log`` / ``_scan_full_log_locked`` reads new log bytes
   (incremental), detects session boundaries, and writes cumulative stats back
   into ``self.state``.
3. The HTTP server calls ``parse_current`` every time ``/api/status`` is
   polled (~every 5 s).  ``parse_current`` reads the last 16 KB of the log
   for live per-file stats, then combines those with the cumulative session
   data already computed by ``scan_full_log`` to produce global progress
   numbers (bytes, files, %, ETA) that span all sessions.
"""

import copy
import json
import logging
import os
import platform
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cloudhop.transfer")

from .notify import notify
from .utils import (
    ERROR_TAIL_BYTES,
    LOG_TAIL_BYTES,
    MAX_HISTORY_ENTRIES,
    MAX_TRANSFERS,
    MIN_DOWNTIME_GAP_SEC,
    MIN_SESSION_ELAPSED_SEC,
    RCLONE_CHECK_TIMEOUT_SEC,
    RCLONE_CONFIG_TIMEOUT_SEC,
    RCLONE_SIZE_TIMEOUT_SEC,
    RE_ACTIVE,
    RE_ACTIVE2,
    RE_ACTIVE3,
    RE_CHECKS_LISTED,
    RE_COPIED,
    RE_COPIED_WITH_TS,
    RE_ELAPSED,
    RE_ERROR_MSG,
    RE_ERRORS,
    RE_FILES_HIST,
    RE_FULL_TRANSFER_ETA,
    RE_SPEED,
    RE_TIMESTAMP,
    RE_TRANSFERRED_BYTES,
    RE_TRANSFERRED_FILES,
    RECENT_FILES_INITIAL_CHUNK,
    RECENT_FILES_MAX_CHUNK,
    SCANNER_INTERVAL_SEC,
    SYSTEM_EXCLUDES,
    _sanitize_rclone_error,
    downsample,
    fmt_bytes,
    fmt_duration,
    get_remote_label,
    parse_elapsed,
    to_bytes,
    validate_exclude_pattern,
    validate_rclone_input,
)

# ---- Standalone rclone helpers (no mutable state needed) ---------------------


def find_rclone() -> Optional[str]:
    """Check if rclone is installed and return its path."""
    return shutil.which("rclone")


def install_rclone() -> str:
    """Auto-install rclone with user permission.

    Returns the path to the installed rclone binary.  Calls ``sys.exit``
    if the installation fails or the user declines.
    """
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
        print("    4. Then run CloudHop again")
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
                return find_rclone()  # type: ignore[return-value]

    print()
    print("  Installation failed. Please install rclone manually:")
    print("  https://rclone.org/install/")
    sys.exit(1)


def ensure_rclone() -> str:
    """Make sure rclone is available, install if needed."""
    path = find_rclone()
    if path:
        return path
    return install_rclone()


def get_existing_remotes() -> List[str]:
    """Get list of configured rclone remotes."""
    try:
        result = subprocess.run(
            ["rclone", "listremotes"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            remotes = [
                r.strip().rstrip(":") for r in result.stdout.strip().split("\n") if r.strip()
            ]
            return remotes
    except Exception:
        pass
    return []


def remote_exists(name: str) -> bool:
    """Check if a remote is already configured."""
    return name in get_existing_remotes()


# ---- rclone command validation -----------------------------------------------

# Flags that are safe in a resumed rclone command.  Only --flag=value forms
# are accepted; bare positional args are allowed only if they look like paths
# (no shell metacharacters).
_KNOWN_RCLONE_FLAGS = {
    "--bwlimit",
    "--buffer-size",
    "--checkers",
    "--checksum",
    "--config",
    "--contimeout",
    "--create-empty-src-dirs",
    "--drive-chunk-size",
    "--dry-run",
    "--exclude",
    "--fast-list",
    "--include",
    "--log-file",
    "--log-level",
    "--low-level-retries",
    "--multi-thread-streams",
    "--no-traverse",
    "--progress",
    "--rc",
    "--rc-addr",
    "--rc-pass",
    "--rc-user",
    "--retries",
    "--stats",
    "--stats-log-level",
    "--timeout",
    "--tpslimit",
    "--transfers",
    "--verbose",
}

_SHELL_META = set(";&|`$(){}!><\n\r\0")


def validate_rclone_cmd(cmd: list) -> bool:
    """Validate that *cmd* looks like a legitimate rclone command.

    Returns True if the command passes validation, False otherwise.
    """
    if not cmd:
        logger.error("validate_rclone_cmd: empty command")
        return False

    # First element must be rclone
    exe = os.path.basename(cmd[0])
    if exe not in ("rclone", "rclone.exe"):
        logger.error("validate_rclone_cmd: executable is not rclone: %s", cmd[0])
        return False

    for arg in cmd[1:]:
        # Check for shell metacharacters
        if any(c in arg for c in _SHELL_META):
            logger.error("validate_rclone_cmd: shell metacharacter in arg: %s", arg)
            return False

        if arg.startswith("--"):
            flag_name = arg.split("=", 1)[0]
            if flag_name not in _KNOWN_RCLONE_FLAGS:
                logger.error("validate_rclone_cmd: unknown flag: %s", flag_name)
                return False
        # Positional args (subcommand like "copy", or paths) are allowed
        # as long as they have no shell metacharacters (checked above)

    return True


# ---- TransferManager --------------------------------------------------------


class TransferManager:
    """Encapsulates all mutable transfer state and transfer-related methods.

    Every piece of module-level mutable state from the original monolith is
    stored as an instance attribute so that multiple ``TransferManager``
    instances can coexist (useful for testing).
    """

    def __init__(self, cm_dir: Optional[str] = None) -> None:
        self.cm_dir: str = cm_dir or os.path.join(os.path.expanduser("~"), ".cloudhop")
        os.makedirs(self.cm_dir, mode=0o700, exist_ok=True)

        # Transfer state
        self.rclone_cmd: List[str] = []
        self.transfer_active: bool = False
        self.rclone_pid: Optional[int] = None
        self._rclone_proc: Optional[subprocess.Popen] = None
        self.log_file: str = os.path.join(self.cm_dir, "cloudhop.log")
        self.state_file: str = os.path.join(self.cm_dir, "cloudhop_state.json")
        self.transfer_label: str = "Source -> Destination"

        # RC API auth (generated per transfer)
        self._rc_user: str = ""
        self._rc_pass: str = ""
        self._rc_port: int = 0

        # Locks (initialized before _load_queue which needs state_lock)
        self.state_lock: threading.RLock = threading.RLock()
        self.transfer_lock: threading.Lock = threading.Lock()
        self._scan_lock: threading.Lock = threading.Lock()
        self._save_lock: threading.Lock = threading.Lock()

        # Transfer queue
        self.queue: List[Dict[str, Any]] = []
        self.queue_file: str = os.path.join(self.cm_dir, "queue.json")
        self._queue_lock: threading.Lock = threading.Lock()
        self._load_queue()

        # Persistent state
        self.state: Dict[str, Any] = self._load_state()

        # Internal flag used by scan_full_log to avoid concurrent size fetches
        self._size_fetching: bool = False

        # Crash backoff tracking and transfer start time
        self._crash_times: list = []
        self._transfer_start_time: Optional[float] = None

        # ETA smoothing (exponential moving average)
        self._speed_ema: float = 0.0
        self._ema_alpha: float = 0.3

        # Rate limit auto-throttle tracking
        self._rate_limit_timestamps: List[float] = []
        self._original_transfers: int = 0
        self._current_transfers: int = 0
        self._throttle_active: bool = False
        self._last_rate_limit_time: float = 0.0

        # Completion notification tracking
        self._completion_notified: bool = False
        self._rate_limited: bool = False

    # ---- helpers -------------------------------------------------------------

    @staticmethod
    def _find_free_port() -> int:
        """Find a free TCP port in range 10000-60000."""
        for _ in range(50):
            port = secrets.randbelow(50000) + 10000
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", port))
                    return port
                except OSError:
                    continue
        raise RuntimeError("Could not find a free port for rclone RC API")

    # ---- path helpers --------------------------------------------------------

    def set_transfer_paths(self, source: str, dest: str) -> None:
        """Set unique log/state file paths and transfer label."""
        transfer_id = secrets.token_hex(8)  # 16 hex chars = 64 bits
        log_file = os.path.join(self.cm_dir, f"cloudhop_{transfer_id}.log")
        state_file = os.path.join(self.cm_dir, f"cloudhop_{transfer_id}_state.json")
        src_label = get_remote_label(source)
        dst_label = get_remote_label(dest)
        label = f"{src_label} -> {dst_label}"
        new_state = self._load_state()
        with self.state_lock:
            self.log_file = log_file
            self.state_file = state_file
            self.transfer_label = label
            self.state = new_state

    # ---- schedule window checker --------------------------------------------

    def is_in_schedule_window(self) -> bool:
        """Check if current time falls within the scheduled transfer window."""
        with self.state_lock:
            schedule = self.state.get("schedule", {})

        if not schedule.get("enabled", False):
            return True  # No schedule = always allowed

        now = datetime.now()
        current_day = now.weekday()  # 0=Monday
        allowed_days = schedule.get("days", [0, 1, 2, 3, 4, 5, 6])
        current_minutes = now.hour * 60 + now.minute

        start_h, start_m = map(int, schedule.get("start_time", "22:00").split(":"))
        end_h, end_m = map(int, schedule.get("end_time", "06:00").split(":"))
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        if start_minutes <= end_minutes:
            # Same-day window (e.g., 09:00 - 17:00)
            if current_day not in allowed_days:
                return False
            return start_minutes <= current_minutes < end_minutes
        else:
            # Overnight window (e.g., 22:00 - 06:00)
            if current_minutes >= start_minutes:
                # Evening side - check today's day
                return current_day in allowed_days
            elif current_minutes < end_minutes:
                # Early morning - window started yesterday
                yesterday = (current_day - 1) % 7
                return yesterday in allowed_days
            else:
                return False

    def _check_schedule(self) -> None:
        """Auto-pause/resume based on schedule window. Called by background_scanner."""
        with self.state_lock:
            schedule = self.state.get("schedule", {})
        if not schedule.get("enabled", False):
            return

        in_window = self.is_in_schedule_window()
        bw_limit_in_window = schedule.get("bw_limit_in_window", "")
        bw_limit_out_window = schedule.get("bw_limit_out_window", "0")

        if in_window and not self.is_rclone_running() and self.rclone_cmd:
            # Window opened - resume transfer
            result = self.resume()
            if result.get("ok"):
                try:
                    from .notify import notify

                    notify("CloudHop", "Transfer resumed (schedule window opened)")
                except Exception:
                    pass
        elif in_window and self.is_rclone_running() and bw_limit_in_window:
            # In window with bandwidth limit - apply in-window limit
            self.set_bandwidth(bw_limit_in_window)

        elif not in_window and self.is_rclone_running():
            if bw_limit_out_window and bw_limit_out_window != "0":
                # Out of window with bandwidth limit - throttle instead of pausing
                self.set_bandwidth(bw_limit_out_window)
            else:
                # Out of window, no bandwidth limit - pause transfer
                result = self.pause()
                if result.get("ok"):
                    try:
                        from .notify import notify

                        notify("CloudHop", "Transfer paused (outside schedule window)")
                    except Exception:
                        pass

    # ---- state persistence ---------------------------------------------------

    def _default_state(self) -> Dict[str, Any]:
        """Return a fresh default state dictionary."""
        return {
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
            "schedule": {
                "enabled": False,
                "start_time": "22:00",
                "end_time": "06:00",
                "days": [0, 1, 2, 3, 4, 5, 6],
                "bw_limit_in_window": "",
                "bw_limit_out_window": "0",
            },
        }

    def _load_state(self) -> Dict[str, Any]:
        """Load persistent state from disk (internal helper used by __init__)."""
        default = self._default_state()
        try:
            with open(self.state_file, "r") as f:
                saved = json.load(f)
                for k, v in default.items():
                    if k not in saved:
                        saved[k] = v
                return saved
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def load_state(self) -> Dict[str, Any]:
        """Public interface: reload state from disk and return it."""
        new_state = self._load_state()
        with self.state_lock:
            self.state = new_state
            return copy.deepcopy(self.state)

    def save_state(self) -> None:
        """Save persistent state to disk."""
        logger.debug("Acquiring _save_lock for state persistence")
        with self._save_lock:
            with self.state_lock:
                try:
                    tmp = self.state_file + ".tmp"
                    with open(tmp, "w") as f:
                        json.dump(self.state, f)
                    os.replace(tmp, self.state_file)
                except Exception as e:
                    logger.warning("Failed to save state: %s", e)

    # ---- rclone process management -------------------------------------------

    def _clear_proc(self) -> None:
        """Clear tracked process state. Caller MUST hold ``state_lock``."""
        self._rclone_proc = None
        self.rclone_pid = None
        self.transfer_active = False

    def is_rclone_running(self) -> bool:
        """Return True if the tracked rclone process is still alive.

        When a ``Popen`` object is available (normal operation),
        ``proc.poll()`` is used -- this is cross-platform and automatically
        reaps zombie processes.

        When only a bare PID is tracked (``--attach-pid`` mode), we fall
        back to POSIX ``os.waitpid`` / ``os.kill(pid, 0)``, or
        ``os.kill(pid, 0)`` on Windows.
        """
        with self.state_lock:
            proc = self._rclone_proc
            pid = self.rclone_pid
            if proc is not None:
                if proc.poll() is None:
                    return True
                self._clear_proc()
                return False
            if not pid:
                return False
            # Attach-pid fallback: no Popen object available.
            # POSIX: reap zombies via waitpid before probing
            if hasattr(os, "WNOHANG"):
                try:
                    waited_pid, _status = os.waitpid(pid, os.WNOHANG)
                    if waited_pid == 0:
                        return True  # still running
                    self._clear_proc()
                    return False
                except ChildProcessError:
                    pass  # not our child, fall through to kill(0)
                except (ProcessLookupError, OSError):
                    self._clear_proc()
                    return False
            # Cross-platform fallback: kill(0) probes without sending a signal
            try:
                os.kill(pid, 0)
                # Verify it's actually rclone, not a recycled PID.
                # psutil is optional -- if unavailable, assume running.
                try:
                    import psutil

                    p = psutil.Process(pid)
                    return "rclone" in p.name().lower()
                except ImportError:
                    return True
                except Exception:
                    return True
            except (ProcessLookupError, OSError):
                self._clear_proc()
                return False

    # ---- full log scanner (session detection + chart history) ----------------

    def scan_full_log(self) -> None:
        """Scan the log to detect sessions and build cumulative state.

        Session detection algorithm (implemented in ``_scan_full_log_locked``):
        rclone resets its ``Elapsed time:`` counter each time it restarts.
        We scan every ``Elapsed time:`` line; when ``elapsed < prev_elapsed *
        0.5`` (i.e. the timer dropped by more than half) AND the previous
        session ran for at least ``MIN_SESSION_ELAPSED_SEC`` (300 s), we
        treat it as a new session boundary.  The previous session's final
        stats are snapshotted at the moment of the drop.

        The scan is incremental: ``last_scan_offset`` in state tracks how far
        we've already read, so subsequent calls only process new bytes.
        """
        with self._scan_lock:
            self._scan_full_log_locked()

    def _scan_full_log_locked(self) -> None:
        if not os.path.exists(self.log_file):
            return

        # Incremental scanning: on first call read everything, on subsequent
        # calls only read from the last offset and carry forward running state.
        with self.state_lock:
            last_offset: int = self.state.get("last_scan_offset", 0)

        with open(self.log_file, "r", encoding="utf-8", errors="replace") as f:
            # Detect log truncation (rotation/restart): if the file is
            # shorter than our last offset, re-scan from the beginning.
            if last_offset > 0:
                f.seek(0, 2)  # seek to end
                file_size = f.tell()
                if file_size < last_offset:
                    logger.info("Log file truncated, resetting scan offset")
                    last_offset = 0
                    f.seek(0)
                else:
                    f.seek(last_offset)
            content: str = f.read()
            new_offset: int = f.tell()

        # If we seeked to a mid-file offset, we may have landed mid-line.
        # Discard the partial first line to avoid corrupt parsing.
        if last_offset > 0 and content:
            first_nl = content.find("\n")
            if first_nl >= 0:
                content = content[first_nl + 1 :]
            else:
                content = ""

        # If nothing new was written, skip processing.
        if not content and last_offset > 0:
            return

        lines: List[str] = content.split("\n")

        # Restore running state from previous incremental scans.
        if last_offset > 0:
            with self.state_lock:
                if not isinstance(self.state.get("_running_sessions"), list):
                    self.state["_running_sessions"] = []
                sessions: List[Dict[str, Any]] = list(self.state.get("_running_sessions", []))
                current_session: Optional[Dict[str, Any]] = self.state.get(
                    "_running_current_session", None
                )
                if current_session is not None and not isinstance(current_session, dict):
                    current_session = None
                if current_session is not None:
                    current_session = dict(current_session)
                prev_elapsed: float = self.state.get("_running_prev_elapsed", -1)
                file_types: Dict[str, int] = dict(self.state.get("all_file_types", {}))
                total_copied_set: Set[str] = set(self.state.get("_running_copied_files_set", []))
                last_ts: Optional[str] = self.state.get("_running_last_ts", None)
                prev_ts: Optional[str] = self.state.get("_running_prev_ts", None)
                prev_transferred_bytes: float = self.state.get("_running_prev_transferred_bytes", 0)
                prev_total_bytes: float = self.state.get("_running_prev_total_bytes", 0)
                prev_files_done: int = self.state.get("_running_prev_files_done", 0)
                prev_files_total: int = self.state.get("_running_prev_files_total", 0)
                # Chart history running state
                speed_hist: List[Optional[float]] = list(self.state.get("_running_speed_hist", []))
                pct_hist: List[Optional[float]] = list(self.state.get("_running_pct_hist", []))
                files_hist: List[Optional[int]] = list(self.state.get("_running_files_hist", []))
                chart_prev_el: float = self.state.get("_running_chart_prev_el", -1)
                cumul_bytes_offset: float = self.state.get("_running_cumul_bytes_offset", 0)
                cumul_files_offset: int = self.state.get("_running_cumul_files_offset", 0)
                session_max_bytes: float = self.state.get("_running_session_max_bytes", 0)
                session_max_files: int = self.state.get("_running_session_max_files", 0)
                first_session_total: float = self.state.get("_running_first_session_total", 0)
                cur_transferred: float = 0
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

        # FIX 1: When doing incremental scanning, the first elapsed value in
        # the new chunk should NOT trigger a session boundary because
        # prev_elapsed is stale from the previous chunk.
        first_elapsed_in_chunk: bool = last_offset > 0

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

                # Chart history: speed and percentage
                if first_session_total == 0:
                    first_session_total = cur_total
                session_max_bytes = max(session_max_bytes, cur_transferred)
                if first_session_total > 0:
                    global_pct_val = (
                        (cumul_bytes_offset + cur_transferred) / first_session_total * 100
                    )
                    pct_hist.append(round(min(global_pct_val, 100), 1))
                spd_str = m_data.group(4)
                sm = RE_SPEED.match(spd_str)
                if sm:
                    v = float(sm.group(1))
                    u = sm.group(2).upper()
                    if u.startswith("K"):
                        v /= 1024
                    elif u.startswith("G"):
                        v *= 1024
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
                bytes_changed = (
                    abs(cur_transferred - prev_transferred_bytes) > 1_000_000
                    if cur_transferred
                    else True
                )
                if (
                    not first_elapsed_in_chunk
                    and chart_prev_el > MIN_SESSION_ELAPSED_SEC
                    and elapsed_sec < chart_prev_el * 0.5
                    and bytes_changed
                ):
                    cumul_bytes_offset += session_max_bytes
                    cumul_files_offset += session_max_files
                    session_max_bytes = 0
                    session_max_files = 0
                    speed_hist.append(None)
                    pct_hist.append(None)
                    files_hist.append(None)
                chart_prev_el = elapsed_sec

                # Session boundary: elapsed dropped >50% means rclone restarted.
                session_bytes_changed = (
                    abs(cur_transferred - prev_transferred_bytes) > 1_000_000
                    if cur_transferred
                    else True
                )
                if (
                    not first_elapsed_in_chunk
                    and prev_elapsed > MIN_SESSION_ELAPSED_SEC
                    and elapsed_sec < prev_elapsed * 0.5
                    and elapsed_sec < 60
                    and session_bytes_changed
                ):
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
                first_elapsed_in_chunk = False

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

        # Build a finalized session list for cumulative calculation.
        finalized_sessions: List[Dict[str, Any]] = list(sessions)
        if current_session:
            cs_copy = dict(current_session)
            cs_copy["end_time"] = cs_copy.get("last_ts", "")
            finalized_sessions.append(cs_copy)

        # FIX 4: Deduplicate sessions with nearly identical start times
        # (within 300 seconds) or sessions that transferred < 1MB.
        if len(finalized_sessions) > 1:
            deduped: List[Dict[str, Any]] = [finalized_sessions[0]]
            for s in finalized_sessions[1:]:
                # Merge sessions that transferred < 1MB (false restarts)
                if (
                    s.get("final_transferred_bytes", 0) < 1_000_000
                    and s is not finalized_sessions[-1]
                ):
                    deduped[-1]["end_time"] = s.get("end_time", deduped[-1].get("end_time", ""))
                    deduped[-1]["final_elapsed_sec"] = max(
                        deduped[-1].get("final_elapsed_sec", 0),
                        s.get("final_elapsed_sec", 0),
                    )
                    continue
                prev_start_str = deduped[-1].get("start_time", "")
                cur_start_str = s.get("start_time", "")
                if prev_start_str and cur_start_str:
                    try:
                        t_prev = datetime.strptime(prev_start_str, "%Y/%m/%d %H:%M:%S")
                        t_cur = datetime.strptime(cur_start_str, "%Y/%m/%d %H:%M:%S")
                        if abs((t_cur - t_prev).total_seconds()) < 300:
                            if s.get("final_transferred_bytes", 0) > deduped[-1].get(
                                "final_transferred_bytes", 0
                            ):
                                s["start_time"] = deduped[-1].get(
                                    "start_time", s.get("start_time", "")
                                )
                                s["session_num"] = deduped[-1].get(
                                    "session_num", s.get("session_num", 0)
                                )
                                deduped[-1] = s
                            else:
                                deduped[-1]["end_time"] = s.get(
                                    "end_time", deduped[-1].get("end_time", "")
                                )
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
            if current_session:
                sessions = finalized_sessions[:-1]
            else:
                sessions = finalized_sessions

        cumulative_bytes: float = 0
        cumulative_files: int = 0
        cumulative_elapsed: float = 0
        for s in finalized_sessions[:-1]:
            cumulative_bytes += s.get("final_transferred_bytes", 0)
            cumulative_files += s.get("final_files_done", 0)
            cumulative_elapsed += s.get("final_elapsed_sec", 0)

        # Get the REAL source size by running 'rclone size' once and caching.
        original_total: float = 0
        original_files: int = 0
        with self.state_lock:
            cached_total = self.state.get("source_size_bytes", 0)
            cached_files = self.state.get("source_size_files", 0)
        if cached_total > 0:
            original_total = cached_total
            original_files = cached_files
        elif finalized_sessions:
            original_total = max((s.get("session_total_bytes", 0) or 0) for s in finalized_sessions)
            original_files = max((s.get("final_files_total", 0) or 0) for s in finalized_sessions)
            # Fetch the authoritative source size by running ``rclone size``
            # once and caching the result.  This runs in a daemon thread
            # because it can take minutes for large remotes (e.g. 100 GB+
            # of cloud storage) and we must not block the log scanner or
            # the HTTP handler.  ``_size_fetching`` is a simple flag to
            # prevent spawning a second thread if the first is still running.
            should_start_size_fetch = False
            with self.state_lock:
                if not self._size_fetching:
                    self._size_fetching = True
                    should_start_size_fetch = True
                    logger.debug("Size fetch flag set atomically under state_lock")
            if should_start_size_fetch:

                def _fetch_source_size() -> None:
                    try:
                        src = self.rclone_cmd[2] if len(self.rclone_cmd) > 2 else ""
                        if not src:
                            return
                        size_cmd = ["rclone", "size", src, "--json"]
                        for excl in SYSTEM_EXCLUDES:
                            size_cmd.append(f"--exclude={excl}")
                        sz_result = subprocess.run(
                            size_cmd,
                            capture_output=True,
                            text=True,
                            timeout=RCLONE_SIZE_TIMEOUT_SEC,
                        )
                        if sz_result.returncode == 0:
                            data = json.loads(sz_result.stdout)
                            with self.state_lock:
                                self.state["source_size_bytes"] = data.get("bytes", 0)
                                self.state["source_size_files"] = data.get("count", 0)
                            self.save_state()
                    except Exception:
                        pass
                    finally:
                        with self.state_lock:
                            self._size_fetching = False

                threading.Thread(target=_fetch_source_size, daemon=True).start()

        # FIX 2: Sanity checks
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

        with self.state_lock:
            self.state["sessions"] = [
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
            self.state["cumulative_transferred_bytes"] = cumulative_bytes
            self.state["cumulative_files_done"] = cumulative_files
            self.state["cumulative_elapsed_sec"] = cumulative_elapsed
            self.state["original_total_bytes"] = original_total
            self.state["original_total_files"] = original_files
            self.state["all_file_types"] = file_types
            self.state["total_copied_count"] = len(total_copied_set)
            _capped_copied = list(total_copied_set)
            if len(_capped_copied) > 50000:
                _capped_copied = _capped_copied[-50000:]
            self.state["_running_copied_files_set"] = _capped_copied

            # Cache chart history for parse_current() to read cheaply
            self.state["cached_speed_history"] = downsample(speed_hist)
            self.state["cached_pct_history"] = downsample(pct_hist)
            self.state["cached_files_history"] = downsample(files_hist)

            # Persist incremental scan offset and running state
            self.state["last_scan_offset"] = new_offset
            self.state["_running_sessions"] = sessions
            self.state["_running_current_session"] = current_session
            self.state["_running_prev_elapsed"] = prev_elapsed
            self.state["_running_last_ts"] = last_ts
            self.state["_running_prev_ts"] = prev_ts
            self.state["_running_prev_transferred_bytes"] = prev_transferred_bytes
            self.state["_running_prev_total_bytes"] = prev_total_bytes
            self.state["_running_prev_files_done"] = prev_files_done
            self.state["_running_prev_files_total"] = prev_files_total
            if len(speed_hist) > MAX_HISTORY_ENTRIES:
                speed_hist = speed_hist[-MAX_HISTORY_ENTRIES:]
            if len(pct_hist) > MAX_HISTORY_ENTRIES:
                pct_hist = pct_hist[-MAX_HISTORY_ENTRIES:]
            if len(files_hist) > MAX_HISTORY_ENTRIES:
                files_hist = files_hist[-MAX_HISTORY_ENTRIES:]
            self.state["_running_speed_hist"] = speed_hist
            self.state["_running_pct_hist"] = pct_hist
            self.state["_running_files_hist"] = files_hist
            self.state["_running_chart_prev_el"] = chart_prev_el
            self.state["_running_cumul_bytes_offset"] = cumul_bytes_offset
            self.state["_running_cumul_files_offset"] = cumul_files_offset
            self.state["_running_session_max_bytes"] = session_max_bytes
            self.state["_running_session_max_files"] = session_max_files
            self.state["_running_first_session_total"] = first_session_total

        self.save_state()

    # ---- parse_current and sub-functions -------------------------------------

    def _parse_tail_stats(
        self, tail: str
    ) -> Tuple[Dict[str, Any], str, str, float, float, List[str]]:
        """Parse the log tail for current transfer stats."""
        result: Dict[str, Any] = {
            "speed": None,
            "eta": None,
            "session_elapsed": "",
            "session_files_done": 0,
            "session_files_total": 0,
            "errors": 0,
            "checks_done": 0,
            "checks_total": 0,
            "listed": 0,
        }
        cur_transferred_str: str = ""
        cur_total_str: str = ""
        cur_transferred_bytes: float = 0
        cur_total_bytes: float = 0

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

        return (
            result,
            cur_transferred_str,
            cur_total_str,
            cur_transferred_bytes,
            cur_total_bytes,
            lines,
        )

    def _parse_active_transfers(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse active transfer items from log lines."""
        active: List[Dict[str, Any]] = []
        for line in lines:
            m = RE_ACTIVE.search(line)
            if m:
                active.append(
                    {
                        "name": m.group(1).strip(),
                        "pct": int(m.group(2)),
                        "size": m.group(3),
                        "speed": m.group(4),
                        "eta": m.group(5),
                    }
                )
            else:
                m2 = RE_ACTIVE2.search(line)
                if m2:
                    active.append(
                        {
                            "name": m2.group(1).strip(),
                            "pct": int(m2.group(2)),
                            "size": m2.group(3),
                            "speed": m2.group(4),
                            "eta": "",
                        }
                    )
                else:
                    m3 = RE_ACTIVE3.search(line)
                    if m3:
                        active.append(
                            {
                                "name": m3.group(1).strip(),
                                "pct": 0,
                                "speed": "",
                                "eta": "",
                            }
                        )
        seen: Dict[str, Dict[str, Any]] = {}
        for t in active:
            seen[t["name"]] = t
        return list(seen.values())

    def _parse_recent_files(self, log_file: Optional[str] = None) -> List[Dict[str, str]]:
        """Find recently copied files from the log."""
        if log_file is None:
            with self.state_lock:
                log_file = self.log_file
        recent_files: List[Dict[str, str]] = []
        chunk_size = RECENT_FILES_INITIAL_CHUNK
        max_chunk = RECENT_FILES_MAX_CHUNK
        try:
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
                            recent_files.append(
                                {
                                    "name": m.group(2).strip(),
                                    "time": m.group(1).split(" ")[1],
                                }
                            )
                    if len(recent_files) >= 15 or chunk_size >= fsize:
                        break
                    chunk_size *= 4
        except (FileNotFoundError, PermissionError):
            return []
        return recent_files[-15:][::-1]

    def _parse_error_messages(self, log_file: Optional[str] = None) -> List[str]:
        """Extract error messages from the log."""
        if log_file is None:
            with self.state_lock:
                log_file = self.log_file
        error_msgs: List[str] = []
        self._rate_limited = False
        try:
            with open(log_file, "rb") as f:
                f.seek(0, 2)
                fsize = f.tell()
                f.seek(max(0, fsize - ERROR_TAIL_BYTES))
                err_tail = f.read().decode("utf-8", errors="replace")
        except (FileNotFoundError, PermissionError):
            return []
        rate_limit_count = 0
        now = time.time()
        for line in err_tail.split("\n"):
            if "ERROR" in line and "Errors:" not in line:
                m = RE_ERROR_MSG.search(line)
                if m:
                    msg = m.group(1).strip()
                    msg_lower = msg.lower()
                    if (
                        "429" in msg
                        or "rate limit" in msg_lower
                        or "too many requests" in msg_lower
                        or "retry after" in msg_lower
                    ):
                        rate_limit_count += 1
                        self._rate_limited = True
                        # Track timestamp for time-window throttle
                        ts_m = RE_TIMESTAMP.search(line)
                        if ts_m:
                            self._rate_limit_timestamps.append(now)
                            self._last_rate_limit_time = now
                        continue
                    if msg not in error_msgs:
                        error_msgs.append(msg)

        # Prune old timestamps (keep only last 60 seconds)
        self._rate_limit_timestamps = [t for t in self._rate_limit_timestamps if now - t < 60]

        # B3: Auto-throttle when 3+ rate limit errors in 60s window
        if len(self._rate_limit_timestamps) >= 3 and self.is_rclone_running():
            self._apply_rate_limit_throttle()

        # B3: Gradual restore after 5 minutes of no rate limit errors
        if (
            self._throttle_active
            and self._last_rate_limit_time > 0
            and now - self._last_rate_limit_time > 300
            and self.is_rclone_running()
        ):
            self._restore_transfers_gradual()

        if self._rate_limited:
            if self._throttle_active:
                summary = (
                    f"Speed reduced - cloud provider rate limit detected "
                    f"({rate_limit_count} occurrences)."
                )
            else:
                summary = (
                    f"Rate limited by provider ({rate_limit_count} occurrences). "
                    "Speed automatically reduced."
                )
            error_msgs.insert(0, summary)
            logger.warning("Rate limit detected (%d occurrences)", rate_limit_count)
        return error_msgs[-5:]

    def _apply_rate_limit_throttle(self) -> None:
        """Reduce rclone --transfers when rate limiting is detected."""
        if self._current_transfers <= 1:
            return
        if not self._original_transfers:
            # Capture original transfers from the rclone command
            for arg in self.rclone_cmd:
                if arg.startswith("--transfers="):
                    try:
                        self._original_transfers = int(arg.split("=")[1])
                    except (ValueError, IndexError):
                        self._original_transfers = 8
                    break
            if not self._original_transfers:
                self._original_transfers = 8
            self._current_transfers = self._original_transfers

        new_transfers = max(1, self._current_transfers // 2)
        if new_transfers == self._current_transfers:
            return

        logger.warning(
            "Proton Drive rate limit detected: %d errors in 60s, reducing transfers %d -> %d",
            len(self._rate_limit_timestamps),
            self._current_transfers,
            new_transfers,
        )
        self._current_transfers = new_transfers
        self._throttle_active = True
        self._set_transfers_rc(new_transfers)

    def _restore_transfers_gradual(self) -> None:
        """Gradually restore transfers after rate limit subsides."""
        if self._current_transfers >= self._original_transfers:
            self._throttle_active = False
            return

        new_transfers = self._current_transfers + 1
        logger.info(
            "Rate limit quiet for 5m, restoring transfers %d -> %d (original: %d)",
            self._current_transfers,
            new_transfers,
            self._original_transfers,
        )
        self._current_transfers = new_transfers
        self._last_rate_limit_time = time.time()  # Reset timer for next increment
        self._set_transfers_rc(new_transfers)

        if self._current_transfers >= self._original_transfers:
            self._throttle_active = False
            logger.info("Transfers fully restored to %d", self._original_transfers)

    def _set_transfers_rc(self, transfers: int) -> None:
        """Change rclone's concurrent transfers via RC API."""
        try:
            rc_cmd = [
                "rclone",
                "rc",
                "options/set",
                "--json",
                json.dumps({"main": {"Transfers": transfers}}),
            ]
            if self._rc_user and self._rc_pass and self._rc_port:
                rc_cmd.extend(
                    [
                        f"--rc-user={self._rc_user}",
                        f"--rc-pass={self._rc_pass}",
                        f"--rc-addr=127.0.0.1:{self._rc_port}",
                    ]
                )
            result = subprocess.run(
                rc_cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("Transfers changed to %d via RC API", transfers)
            else:
                logger.debug("RC API transfers change failed: %s", result.stderr.strip())
        except Exception as e:
            logger.debug("RC API transfers change error: %s", e)

    def parse_current(self) -> Dict[str, Any]:
        """Return a snapshot of current transfer state for the dashboard.

        Called on every ``/api/status`` poll (roughly every 5 s).

        Fast path: reads only the last 16 KB of the log to extract the
        current rclone stats block (speed, ETA, active files, errors).

        Global progress calculation: ``parse_current`` never walks the whole
        log itself.  Instead it reads the cumulative totals already computed
        by ``scan_full_log`` (stored in ``self.state``) and adds the current
        session's partial progress on top:

            global_transferred = cumulative_bytes_from_past_sessions
                                + current_session_transferred_bytes

        This means the global percentage keeps climbing monotonically even
        after rclone restarts mid-transfer.
        """
        with self.state_lock:
            log_file = self.log_file

        if not log_file or not os.path.exists(log_file):
            return {
                "error": "Log file not found",
                "rclone_running": self.is_rclone_running(),
            }

        # Read only the tail of the log for current-session stats (fast).
        with open(log_file, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - LOG_TAIL_BYTES))
            tail = f.read().decode("utf-8", errors="replace")

        (
            result,
            cur_transferred_str,
            cur_total_str,
            cur_transferred_bytes,
            cur_total_bytes,
            lines,
        ) = self._parse_tail_stats(tail)
        result["active"] = self._parse_active_transfers(lines)
        result["recent_files"] = self._parse_recent_files(log_file)
        result["error_messages"] = self._parse_error_messages(log_file)
        result["rate_limited"] = self._rate_limited

        # Process status
        result["finished"] = not self.is_rclone_running()

        # Speed/progress history from cached state (built by scan_full_log)
        with self.state_lock:
            result["speed_history"] = list(self.state.get("cached_speed_history", []))
            result["pct_history"] = list(self.state.get("cached_pct_history", []))
            result["files_history"] = list(self.state.get("cached_files_history", []))

        # Combine current session stats with cumulative totals from all prior
        # sessions.
        with self.state_lock:
            sessions = copy.deepcopy(self.state.get("sessions", []))
            cumul_bytes = self.state.get("cumulative_transferred_bytes", 0)
            cumul_files = self.state.get("cumulative_files_done", 0)
            cumul_elapsed = self.state.get("cumulative_elapsed_sec", 0)
            orig_total = self.state.get("original_total_bytes", 0)
            orig_files = self.state.get("original_total_files", 0)

            global_transferred = cumul_bytes + cur_transferred_bytes

            # Global total = best estimate of actual total data.
            # Use the current session's total (most up-to-date from rclone)
            # combined with cumulative from prior sessions, but take the max
            # with orig_total in case the session total is temporarily low.
            session_based_total = cumul_bytes + cur_total_bytes
            if orig_total > 0:
                global_total = max(orig_total, session_based_total)
            else:
                global_total = max(cur_total_bytes, session_based_total)

            # Never artificially inflate total to match transferred -
            # if transferred > total, it means total is stale, not that
            # we're done. Only cap transferred to total, not the reverse.
            if global_total > 0 and global_transferred > global_total:
                global_transferred = global_total

            global_files_done = cumul_files + result.get("session_files_done", 0)
            session_based_files = cumul_files + result.get("session_files_total", 0)
            if orig_files > 0:
                global_files_total = max(orig_files, session_based_files)
            else:
                global_files_total = session_based_files

            if global_files_total > 0 and global_files_done > global_files_total:
                global_files_done = global_files_total

            # A3: At completion, force file total = files done to fix
            # off-by-one from .DS_Store/.localized/._* exclusion
            if result["finished"] and global_files_done > 0:
                if global_files_done >= global_files_total - 5:
                    global_files_total = global_files_done

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

            global_pct: float = 0
            if global_total > 0:
                global_pct = round(global_transferred / global_total * 100, 1)
                global_pct = min(global_pct, 100)

            files_pct: float = 0
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

            # Clear stale active transfers when transfer is truly complete
            if result["finished"] and global_pct >= 100:
                result["active"] = []
                logger.debug(
                    "Transfer complete (%.1f%%) — cleared active transfers list", global_pct
                )
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
                        real_end = datetime.strptime(s_start, "%Y/%m/%d %H:%M:%S") + timedelta(
                            seconds=s_elapsed
                        )
                        s_end = real_end.strftime("%Y/%m/%d %H:%M:%S")
                    except Exception:
                        pass
                result["sessions"].append(
                    {
                        "num": s.get("num", 0),
                        "start": s_start,
                        "end": s_end,
                        "transferred": fmt_bytes(s.get("transferred", 0)),
                        "files": s.get("files", 0),
                        "elapsed": fmt_duration(s_elapsed),
                        "elapsed_sec": s_elapsed,
                    }
                )

            downtimes: List[Dict[str, Any]] = []
            for i in range(1, len(sessions)):
                prev_start = sessions[i - 1].get("start", "")
                prev_elapsed_val = sessions[i - 1].get("elapsed_sec", 0)
                cur_start = sessions[i].get("start", "")
                if prev_start and cur_start:
                    try:
                        t_prev_start = datetime.strptime(prev_start, "%Y/%m/%d %H:%M:%S")
                        t_prev_real_end = t_prev_start + timedelta(seconds=prev_elapsed_val)
                        t_cur_start = datetime.strptime(cur_start, "%Y/%m/%d %H:%M:%S")
                        gap = (t_cur_start - t_prev_real_end).total_seconds()
                        if gap > MIN_DOWNTIME_GAP_SEC:
                            downtimes.append(
                                {
                                    "after_session": i,
                                    "duration": fmt_duration(gap),
                                    "duration_sec": gap,
                                    "from": t_prev_real_end.strftime("%Y/%m/%d %H:%M:%S"),
                                    "to": cur_start,
                                }
                            )
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
                        result["uptime_pct"] = round(
                            min(global_elapsed_sec / wall_sec * 100, 100), 1
                        )
                    else:
                        result["uptime_pct"] = 0
                except Exception:
                    result["wall_clock"] = "--"
                    result["uptime_pct"] = 0

            result["all_file_types"] = dict(self.state.get("all_file_types", {}))
            result["total_copied_count"] = self.state.get("total_copied_count", 0)
            result["transfer_label"] = self.transfer_label
            result["mode"] = self.state.get("mode", "copy")

            daily: Dict[str, float] = {}
            for s in sessions:
                s_start = s.get("start", "")
                s_bytes = s.get("transferred", 0)
                if s_start:
                    day = s_start[:10]
                    daily[day] = daily.get(day, 0) + s_bytes
            # Sanity check: cap each day's total
            global_xfer = result.get("global_transferred_bytes", 0)
            if global_xfer > 0:
                for day_key in daily:
                    if daily[day_key] > global_xfer:
                        daily[day_key] = global_xfer
            result["daily_stats"] = [
                {
                    "day": d.replace("/", "-"),
                    "bytes": b,
                    "gib": round(b / (1024**3), 1),
                }
                for d, b in sorted(daily.items())
            ]

        result["rclone_running"] = self.is_rclone_running()

        # Extract current bandwidth limit from rclone command for dashboard
        with self.state_lock:
            for arg in self.rclone_cmd:
                if arg.startswith("--bwlimit="):
                    bw_val = arg.split("=", 1)[1]
                    # Convert to dashboard dropdown format (e.g. "10M" -> "10M")
                    result["bw_limit"] = bw_val
                    break

        # B1: ETA smoothing via exponential moving average
        raw_speed = result.get("speed")
        if not result.get("finished"):
            if raw_speed:
                sm = RE_SPEED.match(raw_speed)
                if sm:
                    v = float(sm.group(1))
                    u = sm.group(2).upper()
                    if u.startswith("K"):
                        v /= 1024
                    elif u.startswith("G"):
                        v *= 1024
                    speed_bytes_per_sec = v * 1024 * 1024
                    if speed_bytes_per_sec > 0:
                        if self._speed_ema == 0:
                            self._speed_ema = speed_bytes_per_sec
                        else:
                            self._speed_ema = (
                                self._ema_alpha * speed_bytes_per_sec
                                + (1 - self._ema_alpha) * self._speed_ema
                            )
                        remaining = result.get("global_total_bytes", 0) - result.get(
                            "global_transferred_bytes", 0
                        )
                        if remaining > 0 and self._speed_ema > 0:
                            smoothed_eta_sec = remaining / self._speed_ema
                            result["smoothed_eta"] = fmt_duration(smoothed_eta_sec)
                            result["smoothed_eta_sec"] = smoothed_eta_sec
                        else:
                            result["smoothed_eta"] = "0s"
                            result["smoothed_eta_sec"] = 0
                        result["smoothed_speed"] = fmt_bytes(self._speed_ema) + "/s"
                        logger.debug(
                            "EMA update: platform=%s, raw=%.1f, smoothed=%.1f",
                            sys.platform,
                            speed_bytes_per_sec,
                            self._speed_ema,
                        )
            if self._speed_ema == 0 and not result.get("smoothed_eta"):
                result["smoothed_eta"] = "Calculating..."
                result["smoothed_eta_sec"] = 0

        # Grace period: avoid false "Stopped" status while rclone RC is booting
        just_started = (
            self._transfer_start_time is not None and (time.time() - self._transfer_start_time) < 10
        )
        result["just_started"] = just_started

        return result

    # ---- pause / resume ------------------------------------------------------

    def pause(self) -> Dict[str, Any]:
        """Stop the tracked rclone process (pause the transfer)."""
        logger.info("Pause requested (PID %s)", self.rclone_pid)
        with self.transfer_lock:
            return self._pause_locked()

    def _pause_locked(self) -> Dict[str, Any]:
        # Pause = kill.  rclone has no native pause; we terminate the process
        # and rely on _resume_locked to restart it from scratch.  rclone's
        # built-in deduplication (--copy-dest / size+time checks) means it
        # skips already-transferred files on resume, so no work is lost.
        with self.state_lock:
            proc = self._rclone_proc
            pid = self.rclone_pid
        if not pid:
            return {"ok": False, "msg": "No tracked rclone process"}
        try:
            if proc is not None:
                proc.terminate()
            elif platform.system().lower() == "windows":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                )
            else:
                os.kill(pid, signal.SIGTERM)
            with self.state_lock:
                self._clear_proc()
            self._completion_notified = True  # Don't notify on user-initiated pause
            time.sleep(1)
            self.scan_full_log()
            return {"ok": True, "msg": f"Stopped rclone (PID {pid})"}
        except (ProcessLookupError, OSError):
            with self.state_lock:
                self._clear_proc()
            return {"ok": False, "msg": "rclone process not found"}

    def resume(self) -> Dict[str, Any]:
        """Restart the rclone process using the last-known command."""
        logger.info("Resume requested")
        with self.transfer_lock:
            return self._resume_locked()

    def _resume_locked(self) -> Dict[str, Any]:
        # Resume = restart the exact same rclone command that was used to
        # start the transfer (saved in state["rclone_cmd"]).  rclone will
        # compare file sizes/mtimes at the destination and skip files that
        # already exist, continuing from where it left off.
        if not self.rclone_cmd:
            with self.state_lock:
                self.rclone_cmd = self.state.get("rclone_cmd", [])
        if not self.rclone_cmd:
            return {
                "ok": False,
                "msg": "No transfer configured. Please set up a transfer first.",
            }
        # Validate command loaded from state file before execution
        if not validate_rclone_cmd(self.rclone_cmd):
            logger.error("Resume refused: rclone_cmd failed validation: %s", self.rclone_cmd)
            return {
                "ok": False,
                "msg": "Saved transfer command failed security validation. Please set up a new transfer.",
            }
        if self.is_rclone_running():
            return {"ok": False, "msg": "rclone is already running"}
        self._completion_notified = False
        # Crash backoff: if rclone crashed 3+ times in 5 minutes, wait before retrying
        now = time.time()
        # Clean old entries (older than 5 minutes)
        self._crash_times = [t for t in self._crash_times if now - t < 300]
        if len(self._crash_times) >= 3:
            wait = int(300 - (now - self._crash_times[0]))
            return {
                "ok": False,
                "msg": f"Transfer keeps failing. Waiting {wait}s before retrying. Check your internet connection.",
            }
        self._crash_times.append(now)
        try:
            popen_kwargs = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if platform.system().lower() == "windows":
                popen_kwargs["creationflags"] = (
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                )
            else:
                popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(self.rclone_cmd, **popen_kwargs)
            with self.state_lock:
                self._rclone_proc = proc
                self.rclone_pid = proc.pid
                self.transfer_active = True
                # Increment session counter on resume
                sessions = self.state.get("sessions", [])
                new_session_num = len(sessions) + 1
                sessions.append(
                    {
                        "session_num": new_session_num,
                        "num": new_session_num,
                        "start": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                        "elapsed_sec": 0,
                        "transferred": 0,
                        "files": 0,
                    }
                )
                self.state["sessions"] = sessions
                logger.info("Session counter incremented to %d on resume", new_session_num)
            self.save_state()
            self._transfer_start_time = time.time()
            logger.info("Transfer resumed (PID %s), marked just_started", proc.pid)
            return {"ok": True, "msg": f"Started rclone (PID {proc.pid})"}
        except Exception as e:
            return {"ok": False, "msg": f"Failed to start: {str(e)}"}

    def set_bandwidth(self, limit: str) -> Dict[str, Any]:
        """Change rclone bandwidth limit on the fly via rc API."""
        if not self.is_rclone_running():
            return {"ok": False, "msg": "rclone not running"}
        try:
            rc_cmd = ["rclone", "rc", "core/bwlimit", f"rate={limit}"]
            if self._rc_user and self._rc_pass and self._rc_port:
                rc_cmd.extend(
                    [
                        f"--rc-user={self._rc_user}",
                        f"--rc-pass={self._rc_pass}",
                        f"--rc-addr=127.0.0.1:{self._rc_port}",
                    ]
                )
            result = subprocess.run(
                rc_cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("Bandwidth changed to %s", limit)
                return {"ok": True}
            stderr = result.stderr.strip()
            if "connection refused" in stderr.lower() or "connection failed" in stderr.lower():
                logger.debug("RC API not available, skipping bandwidth change")
            else:
                logger.warning("Bandwidth change failed: %s", stderr)
            return {"ok": False, "msg": stderr}
        except Exception as e:
            err_str = str(e)
            if "connection refused" in err_str.lower():
                logger.debug("RC API not available, skipping bandwidth change")
            else:
                logger.error("Bandwidth change error: %s", e)
            return {"ok": False, "msg": err_str}

    def verify_transfer(self) -> Dict[str, Any]:
        """Run rclone check to verify source matches destination."""
        if self.is_rclone_running():
            return {"ok": False, "msg": "Transfer still running. Wait for it to finish."}
        cmd = self.rclone_cmd or self.state.get("rclone_cmd", [])
        if len(cmd) < 4:
            return {"ok": False, "msg": "No transfer to verify."}
        source = cmd[2]
        dest = cmd[3]
        # Build check command with same excludes
        check_cmd = ["rclone", "check", source, dest, "--one-way"]
        for arg in cmd[4:]:
            if arg.startswith("--exclude="):
                check_cmd.append(arg)
        try:
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
            output = result.stdout + result.stderr
            # Count differences
            diff_lines = [
                ln for ln in output.split("\n") if "ERROR" in ln and "not in" in ln.lower()
            ]
            if result.returncode == 0 and not diff_lines:
                return {
                    "ok": True,
                    "status": "perfect",
                    "msg": "All files verified. Source and destination match perfectly.",
                    "differences": 0,
                }
            return {
                "ok": True,
                "status": "differences",
                "msg": f"Found {len(diff_lines)} difference(s). Some files may not have transferred.",
                "differences": len(diff_lines),
                "details": diff_lines[:20],
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "msg": "Verification timed out. Source may be very large."}
        except Exception as e:
            return {"ok": False, "msg": f"Verification failed: {str(e)}"}

    # ---- transfer queue ------------------------------------------------------

    def _load_queue(self) -> None:
        """Load queue from disk."""
        with self._queue_lock:
            try:
                with open(self.queue_file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.queue = data
                    else:
                        logger.warning("queue.json corrupt (not a list), resetting to empty")
                        self.queue = []
            except FileNotFoundError:
                self.queue = []
            except json.JSONDecodeError:
                logger.warning("queue.json corrupt (invalid JSON), resetting to empty")
                self.queue = []

    def _save_queue(self) -> None:
        """Save queue to disk. Caller MUST hold ``_queue_lock``."""
        try:
            tmp = self.queue_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.queue, f)
            os.replace(tmp, self.queue_file)
        except Exception as e:
            logger.warning("Failed to save queue: %s", e)

    def queue_add(self, transfer_config: Dict[str, Any]) -> Dict[str, Any]:
        """Add a transfer to the queue.

        Args:
            transfer_config: dict with source, dest, and optional options.

        Returns:
            dict with ok=True and the assigned queue_id.
        """
        source = transfer_config.get("source", "")
        dest = transfer_config.get("dest", "")
        if not source or not dest:
            return {"ok": False, "msg": "Missing source or destination"}
        if not validate_rclone_input(source, "source") or not validate_rclone_input(dest, "dest"):
            return {"ok": False, "msg": "Invalid input"}
        queue_id = secrets.token_hex(8)
        entry = {
            "queue_id": queue_id,
            "status": "waiting",
            "added_at": datetime.now().isoformat(),
            "config": {
                "source": source,
                "dest": dest,
                "source_type": transfer_config.get("source_type", ""),
                "dest_type": transfer_config.get("dest_type", ""),
                "transfers": transfer_config.get("transfers", "8"),
                "excludes": transfer_config.get("excludes", []),
                "bw_limit": transfer_config.get("bw_limit", ""),
                "mode": transfer_config.get("mode", "copy"),
            },
        }
        with self._queue_lock:
            self.queue.append(entry)
            self._save_queue()
        logger.info("Queue: added transfer %s (%s -> %s)", queue_id, source, dest)
        return {"ok": True, "queue_id": queue_id}

    def queue_remove(self, queue_id: str) -> bool:
        """Remove a transfer from the queue (only if not active).

        Returns True if removed, False otherwise.
        """
        with self._queue_lock:
            for i, item in enumerate(self.queue):
                if item.get("queue_id") == queue_id:
                    if item.get("status") == "active":
                        logger.info("Queue: cannot remove active transfer %s", queue_id)
                        return False
                    self.queue.pop(i)
                    self._save_queue()
                    logger.info("Queue: removed transfer %s", queue_id)
                    return True
        return False

    def queue_list(self) -> List[Dict[str, Any]]:
        """Return all transfers in the queue with their status."""
        with self._queue_lock:
            logger.debug("Queue: listing %d items", len(self.queue))
            return list(self.queue)

    def queue_reorder(self, queue_id: str, new_position: int) -> bool:
        """Move a transfer to a new position in the queue.

        Returns True if moved, False otherwise.
        """
        with self._queue_lock:
            idx = None
            for i, item in enumerate(self.queue):
                if item.get("queue_id") == queue_id:
                    idx = i
                    break
            if idx is None:
                return False
            if new_position < 0 or new_position >= len(self.queue):
                return False
            if idx == new_position:
                return True
            item = self.queue.pop(idx)
            self.queue.insert(new_position, item)
            self._save_queue()
            logger.debug("Queue: reordered %s from position %d to %d", queue_id, idx, new_position)
            return True

    def queue_process_next(self) -> Dict[str, Any]:
        """Start the next waiting transfer when the current one finishes.

        The queue status update is done in two phases to avoid both deadlocks
        (state_lock must be released before acquiring transfer_lock via
        start_transfer) and TOCTOU races (item is marked "active" before
        the lock is released so other threads skip it).
        """
        if self.is_rclone_running():
            return {"ok": False, "msg": "A transfer is already running"}
        next_item: Optional[Dict[str, Any]] = None
        finished_id: Optional[str] = None
        with self._queue_lock:
            if not self.queue:
                return {"ok": False, "msg": "Queue is empty"}
            # Mark previously active items as completed
            for item in self.queue:
                if item.get("status") in ("active", "starting"):
                    item["status"] = "completed"
                    finished_id = item.get("queue_id")
            # Find next waiting item
            for item in self.queue:
                if item.get("status") == "waiting":
                    next_item = item
                    break
            if next_item is not None:
                next_item["status"] = "starting"
            self._save_queue()
        if next_item is None:
            return {"ok": False, "msg": "No queued transfers"}
        next_id = next_item.get("queue_id", "?")
        if finished_id:
            logger.info("Queue: transfer %s completed, starting next: %s", finished_id, next_id)
        else:
            logger.info("Queue: starting next transfer: %s", next_id)
        # Call start_transfer OUTSIDE _queue_lock to avoid deadlock
        config = next_item.get("config", next_item)
        result = self.start_transfer(config)
        with self._queue_lock:
            if result.get("ok"):
                next_item["status"] = "active"
            elif "already running" in result.get("msg", ""):
                next_item["status"] = "waiting"  # revert for retry
            else:
                next_item["status"] = "failed"
            self._save_queue()
        return result

    # ---- start_transfer ------------------------------------------------------

    def start_transfer(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Start a transfer from the web wizard.

        Validates inputs, sets up per-transfer log/state paths, builds an
        rclone command with performance flags, and launches rclone as a
        detached subprocess.
        """
        with self.transfer_lock:
            return self._start_transfer_locked(body)

    def _start_transfer_locked(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if self.transfer_active or self.is_rclone_running():
            return {"ok": False, "msg": "A transfer is already running"}
        self._completion_notified = False
        self._speed_ema = 0.0
        self._rate_limit_timestamps = []
        self._throttle_active = False
        self._last_rate_limit_time = 0.0

        source: str = body.get("source", "")
        dest: str = body.get("dest", "")
        try:
            transfers = int(body.get("transfers", "8"))
            if not (1 <= transfers <= MAX_TRANSFERS):
                transfers = 8
        except (ValueError, TypeError):
            transfers = 8
        excludes: List[str] = body.get("excludes", [])
        bw_limit: str = body.get("bw_limit", "")
        source_type: str = body.get("source_type", "")
        dest_type: str = body.get("dest_type", "")

        # Proton Drive has strict rate limiting - cap parallel transfers
        if dest_type == "protondrive" and transfers > 2:
            transfers = 2
            logger.info("Proton Drive: capped transfers to %d (rate limit protection)", transfers)
        elif source_type == "protondrive" and transfers > 3:
            transfers = 3
            logger.info("Proton Drive source: capped transfers to %d", transfers)

        self._original_transfers = transfers
        self._current_transfers = transfers

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

        # Verify local paths exist
        if source_type == "local" and not os.path.exists(source):
            return {"ok": False, "msg": f"Path not found: {source}"}
        if dest_type == "local" and not os.path.exists(dest):
            try:
                os.makedirs(dest, exist_ok=True)
            except OSError:
                return {
                    "ok": False,
                    "msg": f"Cannot create folder: {dest}. Please check the path.",
                }

        # Transfer mode: copy (default), sync, or bisync
        mode: str = body.get("mode", "copy")
        if mode not in ("copy", "sync", "bisync"):
            mode = "copy"
        logger.info("Transfer mode: %s", mode)

        if mode == "sync":
            logger.warning("Sync mode will DELETE files in destination that don't exist in source")
        elif mode == "bisync":
            logger.info("Bisync mode: two-way sync between source and destination")

        self.set_transfer_paths(source, dest)

        # Determine rclone subcommand based on mode
        rclone_subcommand = mode if mode in ("sync", "bisync") else "copy"

        self.rclone_cmd = [
            "rclone",
            rclone_subcommand,
            source,
            dest,
            f"--transfers={transfers}",
            "--checkers=16",
            f"--log-file={self.log_file}",
            "--log-level=INFO",
            "--stats=10s",
            "--stats-log-level=INFO",
            "--rc",
        ]

        # Generate random RC API credentials and bind to a random port
        self._rc_user = secrets.token_hex(16)
        self._rc_pass = secrets.token_hex(16)
        self._rc_port = self._find_free_port()
        self.rclone_cmd.extend(
            [
                f"--rc-user={self._rc_user}",
                f"--rc-pass={self._rc_pass}",
                f"--rc-addr=127.0.0.1:{self._rc_port}",
            ]
        )
        logger.info("RC API auth configured on port %d", self._rc_port)

        # Cloud-to-cloud transfers benefit from larger chunks and buffers
        if source_type not in ("local",) and dest_type not in ("local",):
            self.rclone_cmd.extend(
                [
                    "--drive-chunk-size=256M",
                    "--buffer-size=128M",
                    "--multi-thread-streams=16",
                ]
            )

        # Exclude system/metadata files from all transfers
        for excl in SYSTEM_EXCLUDES:
            self.rclone_cmd.append(f"--exclude={excl}")

        for excl in excludes:
            if excl:
                self.rclone_cmd.append(f"--exclude={excl}/**")

        if bw_limit and validate_rclone_input(bw_limit, "bw_limit"):
            # If user entered a bare number (e.g. "10"), append "M" for MB/s
            bw_val = bw_limit.strip()
            try:
                float(bw_val)
                bw_val = bw_val + "M"
            except ValueError:
                pass
            self.rclone_cmd.append(f"--bwlimit={bw_val}")

        if body.get("checksum"):
            self.rclone_cmd.append("--checksum")

        if body.get("fast_list", True):
            self.rclone_cmd.append("--fast-list")

        # Copy empty directories so file count matches preview total
        self.rclone_cmd.append("--create-empty-src-dirs")

        # Proton Drive: limit checkers and add throttling to avoid rate limiting
        if dest_type == "protondrive" or source_type == "protondrive":
            # Override the default --checkers=16 with a safer value
            self.rclone_cmd = [
                "--checkers=4" if flag.startswith("--checkers=") else flag
                for flag in self.rclone_cmd
            ]
            self.rclone_cmd.extend(
                [
                    "--tpslimit=4",
                    "--retries=5",
                    "--low-level-retries=10",
                ]
            )
            logger.info("Proton Drive: applied rate limit protection flags")

        # Bisync: first run requires --resync flag (rclone requirement)
        if mode == "bisync":
            bisync_marker = os.path.join(self.cm_dir, "bisync_initialized")
            if not os.path.exists(bisync_marker):
                self.rclone_cmd.append("--resync")
                logger.info("Bisync: first run, adding --resync flag")
                try:
                    with open(bisync_marker, "w") as f:
                        f.write(datetime.now().isoformat())
                except OSError:
                    pass

        # Save rclone_cmd to state but strip flags that contain credentials.
        # Only strip --flag=value patterns that match known credential flags;
        # never strip positional args (source/dest paths) even if they
        # contain substrings like "user" in a path.
        _CREDENTIAL_FLAGS = {
            "--mega-pass=",
            "--mega-user=",
            "--s3-secret-access-key=",
            "--s3-access-key-id=",
            "--protondrive-password=",
            "--protondrive-username=",
            "--ftp-pass=",
            "--ftp-user=",
            "--sftp-pass=",
            "--sftp-user=",
            "--sftp-key-file=",
            "--rc-pass=",
            "--rc-user=",
        }
        safe_cmd = [
            arg
            for arg in self.rclone_cmd
            if not any(arg.lower().startswith(f) for f in _CREDENTIAL_FLAGS)
        ]
        with self.state_lock:
            self.state["rclone_cmd"] = safe_cmd
            self.state["transfer_label"] = self.transfer_label
            self.state["mode"] = mode
        self.save_state()

        try:
            popen_kwargs = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if platform.system().lower() == "windows":
                popen_kwargs["creationflags"] = (
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                )
            else:
                popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(self.rclone_cmd, **popen_kwargs)
            with self.state_lock:
                self._rclone_proc = proc
                self.rclone_pid = proc.pid
                self.transfer_active = True
            self._transfer_start_time = time.time()
            logger.info("Transfer started (PID %s), marked just_started", proc.pid)
            return {"ok": True, "pid": proc.pid}
        except Exception as e:
            return {"ok": False, "msg": str(e)}

    # ---- configure_remote (API / non-interactive) ----------------------------

    def configure_remote(
        self,
        name: str,
        provider_type: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        twofa: Optional[str] = None,
    ) -> Dict[str, Any]:
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
                return {
                    "ok": False,
                    "needs_credentials": True,
                    "msg": "MEGA requires your email and password.",
                    "user_label": "Email",
                    "pass_label": "Password",
                }
            cmd = [
                "rclone",
                "config",
                "create",
                name,
                provider_type,
                f"user={username}",
                f"pass={password}",
            ]
        elif provider_type == "protondrive":
            if not username or not password:
                return {
                    "ok": False,
                    "needs_credentials": True,
                    "msg": "Use your Proton email and account password (not Bridge password).",
                    "user_label": "Proton Email",
                    "pass_label": "Account Password",
                }
            cmd = [
                "rclone",
                "config",
                "create",
                name,
                provider_type,
                f"username={username}",
                f"password={password}",
            ]
            if twofa:
                cmd.append(f"2fa={twofa}")
        elif provider_type == "s3":
            if not username or not password:
                return {
                    "ok": False,
                    "needs_credentials": True,
                    "msg": "Amazon S3 requires your Access Key ID and Secret Access Key.",
                    "user_label": "Access Key ID",
                    "pass_label": "Secret Access Key",
                }
            cmd = [
                "rclone",
                "config",
                "create",
                name,
                provider_type,
                "provider=AWS",
                f"access_key_id={username}",
                f"secret_access_key={password}",
            ]
        else:
            # OAuth-based providers
            cmd = ["rclone", "config", "create", name, provider_type]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=RCLONE_CONFIG_TIMEOUT_SEC,
            )
            if result.returncode == 0:
                # OneDrive requires drive_id and drive_type to be set
                if provider_type == "onedrive":
                    try:
                        logger.info("OneDrive: configuring drive_id and drive_type")
                        dump = subprocess.run(
                            ["rclone", "config", "dump"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        if dump.returncode == 0:
                            cfg = json.loads(dump.stdout)
                            remote_cfg = cfg.get(name, {})
                            if not remote_cfg.get("drive_id"):
                                drives_result = subprocess.run(
                                    ["rclone", "backend", "drives", f"{name}:"],
                                    capture_output=True,
                                    text=True,
                                    timeout=30,
                                )
                                if drives_result.returncode == 0:
                                    drives = json.loads(drives_result.stdout)
                                    if drives and len(drives) > 0:
                                        drive = drives[0]
                                        drive_id = drive.get("id", "")
                                        drive_type = drive.get("driveType", "personal")
                                        subprocess.run(
                                            [
                                                "rclone",
                                                "config",
                                                "update",
                                                name,
                                                f"drive_id={drive_id}",
                                                f"drive_type={drive_type}",
                                            ],
                                            capture_output=True,
                                            text=True,
                                            timeout=10,
                                        )
                                        logger.info(
                                            "OneDrive: auto-set drive_id=%s drive_type=%s",
                                            drive_id,
                                            drive_type,
                                        )
                                else:
                                    # Fallback: set drive_type and trigger auto-detection via lsd
                                    logger.info("OneDrive: backend drives failed, trying fallback")
                                    subprocess.run(
                                        ["rclone", "config", "update", name, "drive_type=personal"],
                                        capture_output=True,
                                        text=True,
                                        timeout=10,
                                    )
                                    subprocess.run(
                                        ["rclone", "lsd", f"{name}:"],
                                        capture_output=True,
                                        text=True,
                                        timeout=30,
                                    )
                    except Exception as exc:
                        logger.warning("OneDrive: drive_id auto-detection failed: %s", exc)

                # Validate the remote actually works
                if provider_type in ("mega", "protondrive", "s3"):
                    check = subprocess.run(
                        ["rclone", "lsd", f"{name}:"],
                        capture_output=True,
                        text=True,
                        timeout=RCLONE_CHECK_TIMEOUT_SEC,
                    )
                    if check.returncode != 0:
                        subprocess.run(
                            ["rclone", "config", "delete", name],
                            capture_output=True,
                            text=True,
                        )
                        error_msg = (
                            check.stderr.strip().split("\n")[0]
                            if check.stderr
                            else "Invalid credentials"
                        )
                        if any(
                            kw in error_msg.lower()
                            for kw in (
                                "login",
                                "auth",
                                "credential",
                                "password",
                            )
                        ):
                            error_msg = "Invalid username or password. Please check your credentials and try again."
                        return {"ok": False, "msg": error_msg}
                return {"ok": True}
            else:
                return {"ok": False, "msg": _sanitize_rclone_error(result.stderr)}
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "msg": "Configuration timed out. Please try again.",
            }
        except Exception as e:
            return {"ok": False, "msg": _sanitize_rclone_error(str(e))}

    # ---- battery check (macOS) -----------------------------------------------

    def _is_on_battery(self) -> bool:
        """Return True if running on battery power (macOS only)."""
        if platform.system() != "Darwin":
            return False
        try:
            result = subprocess.run(
                ["pmset", "-g", "batt"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "'Battery Power'" in result.stdout
        except Exception:
            return False

    def _check_battery(self) -> None:
        """Auto-pause on battery, auto-resume on AC power."""
        with self.state_lock:
            battery_pause = self.state.get("pause_on_battery", False)
        if not battery_pause:
            return
        on_battery = self._is_on_battery()
        if on_battery and self.is_rclone_running():
            with self.state_lock:
                self.state["_battery_paused"] = True
            self.pause()
            try:
                from .notify import notify

                notify("CloudHop", "Transfer paused (running on battery)")
            except Exception:
                pass
        elif not on_battery and not self.is_rclone_running() and self.rclone_cmd:
            # Only resume if we paused due to battery (not user-initiated pause)
            # and only if the schedule window allows it.
            with self.state_lock:
                was_battery = self.state.get("_battery_paused", False)
            if was_battery and self.is_in_schedule_window():
                with self.state_lock:
                    self.state["_battery_paused"] = False
                self.resume()
                try:
                    from .notify import notify

                    notify("CloudHop", "Transfer resumed (AC power connected)")
                except Exception:
                    pass

    # ---- background scanner --------------------------------------------------

    def background_scanner(self) -> None:
        """Periodically rescan the full log to update session state.

        This method runs in an infinite loop and is intended to be started
        in a daemon thread.
        """
        while True:
            try:
                self.scan_full_log()
                self._check_schedule()
                self._check_battery()
                # A4: Notify on transfer completion
                if (
                    not self.is_rclone_running()
                    and self.rclone_cmd
                    and not self._completion_notified
                ):
                    self._completion_notified = True
                    try:
                        status = self.parse_current()
                        files = status.get("global_files_done", 0)
                        size = status.get("global_transferred", "")
                        pct = status.get("global_pct", 0)
                        duration = status.get("global_elapsed", "")
                        if pct >= 99:
                            title = "CloudHop: Transfer Complete"
                            dur_part = f" in {duration}" if duration else ""
                            msg = f"{files} files ({size}) transferred{dur_part}."
                            logger.info("Sending macOS notification: %s", title)
                            notify(title, msg)
                        elif files > 0:
                            title = "CloudHop: Transfer Failed"
                            errs = status.get("error_messages", [])
                            err_summary = errs[0] if errs else "Check dashboard for details."
                            logger.info("Sending macOS notification: %s", title)
                            notify(title, err_summary)
                    except Exception:
                        pass
                    # Email notification on completion
                    try:
                        from .email_notify import build_completion_email, send_email
                        from .settings import load_settings_with_secrets

                        email_settings = load_settings_with_secrets()
                        if email_settings.get("email_enabled"):
                            status = self.parse_current()
                            pct = status.get("global_pct", 0)
                            files = status.get("global_files_done", 0)
                            should_email = (
                                pct >= 99 and email_settings.get("email_on_complete", True)
                            ) or (
                                pct < 99
                                and files > 0
                                and email_settings.get("email_on_failure", True)
                            )
                            if should_email:
                                from . import __version__

                                subj, body = build_completion_email(status, __version__)
                                if send_email(subj, body, email_settings):
                                    logger.info(
                                        "Email notification sent to %s",
                                        email_settings.get("email_to", ""),
                                    )
                    except Exception:
                        logger.debug("Email notification skipped", exc_info=True)
                # Auto-process queue when current transfer finishes
                if not self.is_rclone_running() and self.queue:
                    self.queue_process_next()
            except Exception:
                logger.exception("Scanner error")
            time.sleep(SCANNER_INTERVAL_SEC)
