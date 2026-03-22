"""Comprehensive tests for cloudhop.transfer.TransferManager."""

import json
import logging
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from cloudhop.transfer import (
    TransferManager,
    get_existing_remotes,
    remote_exists,
    validate_rclone_cmd,
)

_POSIX = sys.platform != "win32"

# ---------------------------------------------------------------------------
# Realistic fake rclone log content
# ---------------------------------------------------------------------------

FAKE_LOG = textwrap.dedent("""\
    2025/06/10 10:00:00 INFO  :
    Transferred:   	  500 MiB / 2.000 GiB, 24%, 50.000 MiB/s, ETA 30s
    Transferred:            5 / 100, 5%
    Errors:                 0
    Checks:         0 / 0, -  Listed 100
    Elapsed time:      30.5s

    2025/06/10 10:00:10 INFO  : holiday_photo.jpg: Copied (new)
    2025/06/10 10:00:12 INFO  : documents/report.pdf: Copied (new)
    2025/06/10 10:00:14 INFO  : music/song.mp3: Copied (new)

    2025/06/10 10:00:20 INFO  :
    Transferred:   	  1.000 GiB / 2.000 GiB, 50%, 55.000 MiB/s, ETA 18s
    Transferred:           10 / 100, 10%
    Errors:                 1
    Checks:        10 / 20, 50%  Listed 200
    Elapsed time:      1m0.0s
    *  bigfile.zip:  45% /500MiB, 30MiB/s, 10s
    *  another.tar.gz:  12% /200MiB, 15MiB/s
    *  streaming_file.dat: transferring

    2025/06/10 10:00:20 ERROR : somefile.txt: failed to copy: connection reset
""")

FAKE_LOG_TWO_SESSIONS = textwrap.dedent("""\
    2025/06/10 10:00:00 INFO  :
    Transferred:   	  500 MiB / 2.000 GiB, 24%, 50.000 MiB/s, ETA 30s
    Transferred:            5 / 100, 5%
    Errors:                 0
    Checks:         0 / 0, -  Listed 100
    Elapsed time:      10m0.0s

    2025/06/10 10:10:00 INFO  :
    Transferred:   	  1.000 GiB / 2.000 GiB, 50%, 55.000 MiB/s, ETA 18s
    Transferred:           50 / 100, 50%
    Errors:                 0
    Checks:         0 / 0, -  Listed 100
    Elapsed time:      20m0.0s

    2025/06/10 10:30:00 INFO  :
    Transferred:   	  200 MiB / 2.000 GiB, 10%, 40.000 MiB/s, ETA 45s
    Transferred:            2 / 100, 2%
    Errors:                 0
    Checks:         0 / 0, -  Listed 100
    Elapsed time:      30s

    2025/06/10 10:32:00 INFO  :
    Transferred:   	  800 MiB / 2.000 GiB, 39%, 60.000 MiB/s, ETA 20s
    Transferred:           40 / 100, 40%
    Errors:                 0
    Checks:         0 / 0, -  Listed 100
    Elapsed time:      10m0.0s
""")

FAKE_LOG_EMPTY = ""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def manager(tmp_path):
    """Create a TransferManager with a temporary directory."""
    return TransferManager(cm_dir=str(tmp_path))


@pytest.fixture
def manager_with_log(tmp_path):
    """Create a manager with a fake rclone log file."""
    m = TransferManager(cm_dir=str(tmp_path))
    m.log_file = str(tmp_path / "test.log")
    with open(m.log_file, "w") as f:
        f.write(FAKE_LOG)
    return m


@pytest.fixture
def manager_with_two_session_log(tmp_path):
    """Create a manager with a two-session log (elapsed time drops)."""
    m = TransferManager(cm_dir=str(tmp_path))
    m.log_file = str(tmp_path / "two_session.log")
    with open(m.log_file, "w") as f:
        f.write(FAKE_LOG_TWO_SESSIONS)
    return m


# ===========================================================================
# State Management
# ===========================================================================


class TestStateManagement:
    def test_load_state_default(self, manager):
        """When no state file exists, _load_state returns the default dict."""
        state = manager.state
        assert state["sessions"] == []
        assert state["original_total_bytes"] == 0
        assert state["original_total_files"] == 0
        assert state["last_elapsed_sec"] == 0
        assert state["cumulative_transferred_bytes"] == 0
        assert state["cumulative_files_done"] == 0
        assert state["cumulative_elapsed_sec"] == 0
        assert state["all_file_types"] == {}
        assert state["total_copied_count"] == 0
        assert state["speed_samples"] == []

    def test_load_state_from_file(self, manager):
        """When a valid JSON state file exists, it is loaded correctly."""
        saved = manager._default_state()
        saved["original_total_bytes"] = 999999
        saved["sessions"] = [{"num": 1, "start": "2025/01/01 00:00:00"}]
        with open(manager.state_file, "w") as f:
            json.dump(saved, f)

        loaded = manager.load_state()
        assert loaded["original_total_bytes"] == 999999
        assert len(loaded["sessions"]) == 1

    def test_load_state_corrupt_file(self, manager):
        """When the state file contains invalid JSON, defaults are returned."""
        with open(manager.state_file, "w") as f:
            f.write("NOT VALID JSON {{{")

        loaded = manager.load_state()
        assert loaded == manager._default_state()

    def test_load_state_missing_keys_filled(self, manager):
        """When saved state is missing some keys, defaults fill them in."""
        with open(manager.state_file, "w") as f:
            json.dump({"original_total_bytes": 42}, f)

        loaded = manager.load_state()
        assert loaded["original_total_bytes"] == 42
        assert loaded["sessions"] == []
        assert loaded["speed_samples"] == []

    def test_save_state_atomic(self, manager):
        """save_state writes to .tmp then replaces (atomic write)."""
        manager.state["original_total_bytes"] = 123456
        manager.save_state()

        # The tmp file should NOT exist after a successful save
        assert not os.path.exists(manager.state_file + ".tmp")
        # The real file should exist with correct content
        with open(manager.state_file, "r") as f:
            data = json.load(f)
        assert data["original_total_bytes"] == 123456

    def test_save_state_creates_file(self, manager):
        """save_state creates the state file if it doesn't exist."""
        assert not os.path.exists(manager.state_file)
        manager.save_state()
        assert os.path.exists(manager.state_file)

    def test_save_state_overwrites(self, manager):
        """save_state overwrites a previously saved file."""
        manager.state["original_total_bytes"] = 100
        manager.save_state()
        manager.state["original_total_bytes"] = 200
        manager.save_state()

        with open(manager.state_file, "r") as f:
            data = json.load(f)
        assert data["original_total_bytes"] == 200

    def test_set_transfer_paths(self, manager):
        """set_transfer_paths sets log_file, state_file, and transfer_label."""
        manager.set_transfer_paths("gdrive:photos", "onedrive:backup")

        assert "cloudhop_" in manager.log_file
        assert manager.log_file.endswith(".log")
        assert "cloudhop_" in manager.state_file
        assert manager.state_file.endswith("_state.json")
        assert "Google Drive" in manager.transfer_label
        assert "OneDrive" in manager.transfer_label

    def test_set_transfer_paths_uses_random_id(self, manager):
        """Each call generates a unique random transfer ID (64-bit)."""
        manager.set_transfer_paths("mega:stuff", "/tmp/local")
        log1 = manager.log_file
        state1 = manager.state_file

        manager.set_transfer_paths("mega:stuff", "/tmp/local")
        # Random IDs: each call produces different paths
        assert manager.log_file != log1
        assert manager.state_file != state1

    def test_transfer_id_is_16_hex_chars(self, manager):
        """Transfer ID should be 16 hex characters (64 bits)."""
        import re

        manager.set_transfer_paths("gdrive:test", "onedrive:test")
        # Extract the transfer ID from the log filename
        filename = os.path.basename(manager.log_file)
        # Format: cloudhop_<id>.log
        tid = filename.replace("cloudhop_", "").replace(".log", "")
        assert re.match(r"^[0-9a-f]{16}$", tid), f"Transfer ID {tid!r} is not 16 hex chars"


# ===========================================================================
# Transfer Control (is_rclone_running, pause, resume, start_transfer)
# ===========================================================================


class TestTransferControl:
    def test_is_rclone_running_no_pid(self, manager):
        """Returns False when no pid is tracked."""
        manager.rclone_pid = None
        assert manager.is_rclone_running() is False

    @pytest.mark.skipif(not _POSIX, reason="os.WNOHANG is POSIX-only")
    @patch("os.waitpid", return_value=(0, 0))
    def test_is_rclone_running_with_pid_alive(self, mock_waitpid, manager):
        """Returns True when os.waitpid says the process is still running."""
        manager.rclone_pid = 12345
        assert manager.is_rclone_running() is True
        mock_waitpid.assert_called_once_with(12345, os.WNOHANG)

    @pytest.mark.skipif(not _POSIX, reason="os.WNOHANG is POSIX-only")
    @patch("os.waitpid", return_value=(12345, 0))
    def test_is_rclone_running_with_pid_exited(self, mock_waitpid, manager):
        """Returns False and clears pid when process has exited."""
        manager.rclone_pid = 12345
        assert manager.is_rclone_running() is False
        assert manager.rclone_pid is None

    @pytest.mark.skipif(not _POSIX, reason="os.WNOHANG is POSIX-only")
    @patch("os.waitpid", side_effect=ChildProcessError)
    @patch("os.kill")
    def test_is_rclone_running_not_child_but_alive(self, mock_kill, mock_waitpid, manager):
        """Falls back to kill(0) when not our child; returns True if alive."""
        manager.rclone_pid = 99999
        assert manager.is_rclone_running() is True
        mock_kill.assert_called_once_with(99999, 0)

    @pytest.mark.skipif(not _POSIX, reason="os.WNOHANG is POSIX-only")
    @patch("os.waitpid", side_effect=ChildProcessError)
    @patch("os.kill", side_effect=ProcessLookupError)
    def test_is_rclone_running_not_child_and_dead(self, mock_kill, mock_waitpid, manager):
        """Falls back to kill(0); returns False if process is gone."""
        manager.rclone_pid = 99999
        assert manager.is_rclone_running() is False
        assert manager.rclone_pid is None

    @pytest.mark.skipif(_POSIX, reason="Windows-specific: kill(0) probe")
    @patch("os.kill")
    def test_is_rclone_running_alive_windows(self, mock_kill, manager):
        """On Windows, kill(0) probes existence; returns True if alive."""
        manager.rclone_pid = 12345
        assert manager.is_rclone_running() is True
        mock_kill.assert_called_once_with(12345, 0)

    @pytest.mark.skipif(_POSIX, reason="Windows-specific: kill(0) probe")
    @patch("os.kill", side_effect=ProcessLookupError)
    def test_is_rclone_running_dead_windows(self, mock_kill, manager):
        """On Windows, kill(0) raises ProcessLookupError when process is gone."""
        manager.rclone_pid = 12345
        assert manager.is_rclone_running() is False
        assert manager.rclone_pid is None

    @pytest.mark.skipif(not _POSIX, reason="POSIX pause uses os.kill(SIGTERM)")
    @patch("os.kill")
    @patch("time.sleep")
    def test_pause_kills_process(self, mock_sleep, mock_kill, manager):
        """pause() sends SIGTERM to the tracked process."""
        manager.rclone_pid = 5555
        manager.log_file = "/nonexistent/log"  # scan_full_log will no-op

        result = manager.pause()
        assert result["ok"] is True
        assert "5555" in result["msg"]
        mock_kill.assert_called_once_with(5555, signal.SIGTERM)
        assert manager.rclone_pid is None

    @pytest.mark.skipif(_POSIX, reason="Windows pause uses taskkill")
    @patch("cloudhop.transfer.platform.system", return_value="Windows")
    @patch("subprocess.run")
    @patch("time.sleep")
    def test_pause_kills_process_windows(self, mock_sleep, mock_run, mock_sys, manager):
        """pause() uses taskkill on Windows."""
        mock_run.return_value = MagicMock(returncode=0)
        manager.rclone_pid = 5555
        manager.log_file = "/nonexistent/log"

        result = manager.pause()
        assert result["ok"] is True
        assert "5555" in result["msg"]
        mock_run.assert_called_once_with(
            ["taskkill", "/F", "/T", "/PID", "5555"], capture_output=True, timeout=10
        )
        assert manager.rclone_pid is None

    def test_pause_no_process(self, manager):
        """pause() returns error when no process is tracked."""
        manager.rclone_pid = None
        result = manager.pause()
        assert result["ok"] is False
        assert "No tracked" in result["msg"]

    @pytest.mark.skipif(not _POSIX, reason="POSIX pause uses os.kill")
    @patch("os.kill", side_effect=ProcessLookupError)
    @patch("time.sleep")
    def test_pause_process_already_gone(self, mock_sleep, mock_kill, manager):
        """pause() handles the case where the process already exited."""
        manager.rclone_pid = 7777
        result = manager.pause()
        assert result["ok"] is False
        assert "not found" in result["msg"]

    @patch("cloudhop.transfer.platform.system", return_value="Linux")
    @patch("subprocess.Popen")
    def test_resume_starts_process(self, mock_popen, mock_sys, manager):
        """resume() starts a new rclone process using the saved command."""
        mock_proc = MagicMock()
        mock_proc.pid = 9999
        mock_popen.return_value = mock_proc

        manager.rclone_cmd = ["rclone", "copy", "src:", "dst:"]
        manager.rclone_pid = None

        result = manager.resume()
        assert result["ok"] is True
        assert manager.rclone_pid == 9999
        mock_popen.assert_called_once()

    @patch("os.kill")
    @patch("os.waitpid", return_value=(0, 0))
    def test_resume_already_running(self, mock_waitpid, mock_kill, manager):
        """resume() returns error when rclone is already running."""
        manager.rclone_cmd = ["rclone", "copy", "src:", "dst:"]
        manager.rclone_pid = 1234

        result = manager.resume()
        assert result["ok"] is False
        assert "already running" in result["msg"]

    def test_resume_no_command(self, manager):
        """resume() returns error when no command is configured."""
        manager.rclone_cmd = []
        result = manager.resume()
        assert result["ok"] is False
        assert "No transfer configured" in result["msg"]

    @patch("subprocess.Popen", side_effect=FileNotFoundError("rclone not found"))
    def test_resume_popen_failure(self, mock_popen, manager):
        """resume() handles Popen failure gracefully."""
        manager.rclone_cmd = ["rclone", "copy", "src:", "dst:"]
        result = manager.resume()
        assert result["ok"] is False
        assert "Failed to start" in result["msg"]

    def test_start_transfer_validates_input(self, manager):
        """start_transfer rejects missing source or dest."""
        result = manager.start_transfer({"source": "", "dest": "/tmp/x"})
        assert result["ok"] is False
        assert "Missing" in result["msg"]

        result = manager.start_transfer({"source": "/tmp/x", "dest": ""})
        assert result["ok"] is False

    def test_start_transfer_rejects_flags(self, manager):
        """start_transfer rejects source/dest starting with --."""
        result = manager.start_transfer(
            {
                "source": "--config=/etc/passwd",
                "dest": "/tmp/safe",
            }
        )
        assert result["ok"] is False
        assert "Invalid" in result["msg"]

        result = manager.start_transfer(
            {
                "source": "/tmp/safe",
                "dest": "--some-flag",
            }
        )
        assert result["ok"] is False

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_start_transfer_builds_command(self, mock_exists, mock_popen, manager):
        """start_transfer builds a proper rclone command."""
        mock_proc = MagicMock()
        mock_proc.pid = 4444
        mock_popen.return_value = mock_proc

        result = manager.start_transfer(
            {
                "source": "/local/photos",
                "dest": "gdrive:backup",
                "source_type": "local",
                "dest_type": "drive",
                "transfers": "4",
                "excludes": ["node_modules"],
                "bw_limit": "10M",
                "checksum": True,
            }
        )
        assert result["ok"] is True
        assert result["pid"] == 4444

        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "rclone"
        assert cmd[1] == "copy"
        assert cmd[2] == "/local/photos"
        assert cmd[3] == "gdrive:backup"
        assert "--transfers=4" in cmd
        assert "--checksum" in cmd
        assert "--bwlimit=10M" in cmd
        assert any("--exclude=node_modules/**" in c for c in cmd)

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_start_transfer_cloud_to_cloud_flags(self, mock_exists, mock_popen, manager):
        """Cloud-to-cloud transfers get extra performance flags."""
        mock_proc = MagicMock()
        mock_proc.pid = 5555
        mock_popen.return_value = mock_proc

        manager.start_transfer(
            {
                "source": "gdrive:src",
                "dest": "onedrive:dst",
                "source_type": "drive",
                "dest_type": "onedrive",
            }
        )
        cmd = mock_popen.call_args[0][0]
        assert "--drive-chunk-size=256M" in cmd
        assert "--buffer-size=128M" in cmd

    @patch("os.kill")
    @patch("os.waitpid", return_value=(0, 0))
    def test_start_transfer_lock_prevents_concurrent(self, mock_waitpid, mock_kill, manager):
        """start_transfer rejects a second transfer while one is running."""
        manager.transfer_active = True
        manager.rclone_pid = 1111

        result = manager.start_transfer(
            {
                "source": "/tmp/a",
                "dest": "/tmp/b",
                "source_type": "local",
                "dest_type": "local",
            }
        )
        assert result["ok"] is False
        assert "already running" in result["msg"]

    def test_start_transfer_rejects_invalid_excludes(self, manager):
        """start_transfer rejects exclude patterns with shell injection chars."""
        result = manager.start_transfer(
            {
                "source": "/tmp/a",
                "dest": "/tmp/b",
                "source_type": "local",
                "dest_type": "local",
                "excludes": ["valid", "bad{pattern}"],
            }
        )
        assert result["ok"] is False

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_start_transfer_invalid_transfers_count(self, mock_exists, mock_popen, manager):
        """Invalid transfers count falls back to 8."""
        mock_proc = MagicMock()
        mock_proc.pid = 6666
        mock_popen.return_value = mock_proc

        manager.start_transfer(
            {
                "source": "/tmp/a",
                "dest": "/tmp/b",
                "source_type": "local",
                "dest_type": "local",
                "transfers": "not_a_number",
            }
        )
        cmd = mock_popen.call_args[0][0]
        assert "--transfers=8" in cmd

    def test_start_transfer_nonexistent_local_source(self, manager):
        """start_transfer rejects a local source path that doesn't exist."""
        result = manager.start_transfer(
            {
                "source": "/nonexistent/path/that/does/not/exist",
                "dest": "/tmp/b",
                "source_type": "local",
                "dest_type": "local",
            }
        )
        assert result["ok"] is False
        assert "not found" in result["msg"].lower() or "Path not found" in result["msg"]


# ===========================================================================
# Log Parsing
# ===========================================================================


class TestLogParsing:
    def test_parse_current_no_log(self, manager):
        """parse_current returns error when no log file exists."""
        manager.log_file = "/nonexistent/path/nofile.log"
        result = manager.parse_current()
        assert "error" in result
        assert "Log file not found" in result["error"]

    def test_parse_current_with_log(self, manager_with_log):
        """parse_current parses a realistic log and returns expected fields."""
        m = manager_with_log
        m.rclone_pid = None
        result = m.parse_current()

        # Basic fields exist
        assert "global_transferred" in result
        assert "global_total" in result
        assert "global_pct" in result
        assert "global_files_done" in result
        assert "errors" in result
        assert "recent_files" in result
        assert "active" in result
        assert "error_messages" in result

        # The last stats block has 1 error
        assert result["errors"] == 1

        # Recent files should include the copied files
        recent_names = [f["name"] for f in result["recent_files"]]
        assert any("holiday_photo.jpg" in n for n in recent_names)
        assert any("report.pdf" in n for n in recent_names)
        assert any("song.mp3" in n for n in recent_names)

        # Active transfers parsed
        active_names = [a["name"] for a in result["active"]]
        assert "bigfile.zip" in active_names
        assert "another.tar.gz" in active_names
        assert "streaming_file.dat" in active_names

        # Speed and ETA from the last matching line
        assert result["speed"] is not None
        assert result["eta"] is not None

        # Error messages
        assert len(result["error_messages"]) >= 1
        assert any("somefile.txt" in msg for msg in result["error_messages"])

    def test_parse_current_finished_flag(self, manager_with_log):
        """finished is True when rclone is not running."""
        m = manager_with_log
        m.rclone_pid = None
        result = m.parse_current()
        assert result["finished"] is True

    @patch("os.kill")
    @patch("os.waitpid", return_value=(0, 0))
    def test_parse_current_running_flag(self, mock_waitpid, mock_kill, manager_with_log):
        """finished is False when rclone is running."""
        m = manager_with_log
        m.rclone_pid = 1234
        result = m.parse_current()
        assert result["finished"] is False
        assert result["rclone_running"] is True

    def test_parse_tail_stats(self, manager_with_log):
        """_parse_tail_stats correctly parses transfer bytes, files, errors."""
        m = manager_with_log
        with open(m.log_file, "r") as f:
            tail = f.read()

        result, xfer_str, total_str, xfer_bytes, total_bytes, lines = m._parse_tail_stats(tail)

        # Last matching line: 1.000 GiB / 2.000 GiB
        assert xfer_bytes > 0
        assert total_bytes > 0
        assert result["errors"] == 1
        assert result["session_files_done"] == 10
        assert result["session_files_total"] == 100

    def test_parse_active_transfers(self, manager_with_log):
        """_parse_active_transfers parses all three active transfer formats."""
        lines = FAKE_LOG.split("\n")
        active = manager_with_log._parse_active_transfers(lines)

        names = {a["name"] for a in active}
        assert "bigfile.zip" in names
        assert "another.tar.gz" in names
        assert "streaming_file.dat" in names

        # bigfile.zip has full info
        bf = next(a for a in active if a["name"] == "bigfile.zip")
        assert bf["pct"] == 45
        assert bf["eta"] == "10s"

        # another.tar.gz has no ETA (RE_ACTIVE2 format)
        at = next(a for a in active if a["name"] == "another.tar.gz")
        assert at["pct"] == 12
        assert at["eta"] == ""

        # streaming_file.dat is just "transferring"
        sd = next(a for a in active if a["name"] == "streaming_file.dat")
        assert sd["pct"] == 0

    def test_parse_recent_files(self, manager_with_log):
        """_parse_recent_files extracts copied file names with timestamps."""
        recent = manager_with_log._parse_recent_files()
        assert len(recent) == 3
        # Most recent first (reversed)
        assert "song.mp3" in recent[0]["name"]
        assert recent[0]["time"]  # has a time component

    def test_parse_error_messages(self, manager_with_log):
        """_parse_error_messages extracts ERROR lines from the log."""
        errors = manager_with_log._parse_error_messages()
        assert len(errors) >= 1
        assert any("somefile.txt" in e for e in errors)

    def test_scan_full_log_empty(self, manager):
        """scan_full_log does nothing when the log file doesn't exist."""
        manager.log_file = "/nonexistent/log.log"
        manager.scan_full_log()  # should not raise
        assert manager.state["sessions"] == []

    def test_scan_full_log_single_session(self, manager_with_log):
        """scan_full_log detects a single session from a continuous log."""
        m = manager_with_log
        m.scan_full_log()

        sessions = m.state["sessions"]
        assert len(sessions) >= 1
        # Files and bytes should be tracked
        assert m.state["all_file_types"] != {}
        assert m.state["total_copied_count"] == 3  # 3 Copied (new) lines

    def test_scan_full_log_session_boundary(self, manager_with_two_session_log):
        """scan_full_log detects a session boundary when elapsed drops >50%."""
        m = manager_with_two_session_log
        m.scan_full_log()

        sessions = m.state["sessions"]
        # Elapsed goes 10m -> 20m then drops to 2m -> 10m
        # That drop from 20m to 2m should create a session boundary
        assert len(sessions) >= 2

    def test_scan_full_log_file_types(self, manager_with_log):
        """scan_full_log tracks file extensions of copied files."""
        m = manager_with_log
        m.scan_full_log()

        ft = m.state["all_file_types"]
        assert "jpg" in ft
        assert "pdf" in ft
        assert "mp3" in ft

    def test_scan_full_log_incremental(self, manager_with_log):
        """scan_full_log supports incremental scanning."""
        m = manager_with_log

        # First scan
        m.scan_full_log()
        first_copied = m.state["total_copied_count"]
        assert first_copied == 3

        # Append more data
        with open(m.log_file, "a") as f:
            f.write("\n2025/06/10 10:01:00 INFO  : newfile.txt: Copied (new)\n")
            f.write("Transferred:   \t  1.500 GiB / 2.000 GiB, 75%, 60.000 MiB/s, ETA 8s\n")
            f.write("Transferred:           15 / 100, 15%\n")
            f.write("Errors:                 1\n")
            f.write("Elapsed time:      1m30.0s\n")

        # Second scan should pick up the new file
        m.scan_full_log()
        assert m.state["total_copied_count"] == 4

    def test_scan_full_log_saves_state(self, manager_with_log):
        """scan_full_log persists state to disk."""
        m = manager_with_log
        m.scan_full_log()
        assert os.path.exists(m.state_file)

        with open(m.state_file, "r") as f:
            data = json.load(f)
        assert "sessions" in data

    def test_parse_current_combines_sessions(self, manager_with_two_session_log):
        """parse_current combines cumulative state from scan with current tail."""
        m = manager_with_two_session_log
        m.rclone_pid = None
        m.scan_full_log()
        result = m.parse_current()

        # Should have global stats
        assert result["global_pct"] >= 0
        assert result["global_files_done"] >= 0
        assert "transfer_label" in result


# ===========================================================================
# Remote Configuration
# ===========================================================================


class TestConfigureRemote:
    def test_configure_remote_local(self, manager):
        """Local provider returns ok immediately, no subprocess calls."""
        result = manager.configure_remote("mylocal", "local")
        assert result["ok"] is True

    @patch("cloudhop.transfer.remote_exists", return_value=True)
    def test_configure_remote_already_exists(self, mock_exists, manager):
        """Already-configured remote returns ok with message."""
        result = manager.configure_remote("gdrive", "drive")
        assert result["ok"] is True
        assert "Already configured" in result["msg"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_configure_remote_oauth(self, mock_run, mock_exists, manager):
        """OAuth provider (drive) calls rclone config create."""
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        result = manager.configure_remote("gdrive", "drive")
        assert result["ok"] is True

        # Verify the rclone config create command was called
        cmd = mock_run.call_args_list[0][0][0]
        assert cmd == ["rclone", "config", "create", "gdrive", "drive"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    def test_configure_remote_mega_needs_credentials(self, mock_exists, manager):
        """MEGA without credentials returns needs_credentials."""
        result = manager.configure_remote("mymega", "mega")
        assert result["ok"] is False
        assert result["needs_credentials"] is True
        assert "Email" in result["user_label"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_configure_remote_mega_with_credentials(self, mock_run, mock_exists, manager):
        """MEGA with credentials calls config create with args then lsd."""
        # First call: rclone config create (with user/pass args)
        # Second call: rclone lsd (validation)
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        result = manager.configure_remote(
            "mymega", "mega", username="user@example.com", password="secret"
        )
        assert result["ok"] is True

        # Verify config create was called with credential args
        cmd = mock_run.call_args_list[0][0][0]
        assert "rclone" in cmd
        assert "config" in cmd
        assert "create" in cmd
        assert "user=user@example.com" in cmd
        assert "pass=secret" in cmd

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    def test_configure_remote_s3_needs_credentials(self, mock_exists, manager):
        """S3 without credentials returns needs_credentials."""
        result = manager.configure_remote("mys3", "s3")
        assert result["ok"] is False
        assert result["needs_credentials"] is True
        assert "Access Key" in result["user_label"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_configure_remote_s3_args(self, mock_run, mock_exists, manager):
        """S3 configuration passes credentials as config create args."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # config create
            MagicMock(returncode=0, stdout="", stderr=""),  # lsd check
        ]

        result = manager.configure_remote(
            "mys3", "s3", username="AKIAXXXXXXX", password="secretkey123"
        )
        assert result["ok"] is True

        cmd = mock_run.call_args_list[0][0][0]
        assert "provider=AWS" in cmd
        assert "access_key_id=AKIAXXXXXXX" in cmd
        assert "secret_access_key=secretkey123" in cmd

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    def test_configure_remote_protondrive_needs_credentials(self, mock_exists, manager):
        """Proton Drive without credentials returns needs_credentials."""
        result = manager.configure_remote("myproton", "protondrive")
        assert result["ok"] is False
        assert result["needs_credentials"] is True
        assert "Email" in result["user_label"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_configure_remote_timeout(self, mock_run, mock_exists, manager):
        """Configuration timeout is handled gracefully."""
        import subprocess as sp

        mock_run.side_effect = sp.TimeoutExpired(cmd="rclone", timeout=120)

        result = manager.configure_remote("gdrive", "drive")
        assert result["ok"] is False
        assert "timed out" in result["msg"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_configure_remote_failure(self, mock_run, mock_exists, manager):
        """rclone config create failure returns sanitized error."""
        mock_run.return_value = MagicMock(
            returncode=1, stderr="ERROR: some rclone error\n", stdout=""
        )
        result = manager.configure_remote("gdrive", "drive")
        assert result["ok"] is False

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    def test_configure_remote_rejects_flag_injection_username(self, mock_exists, manager):
        """configure_remote rejects usernames starting with --."""
        result = manager.configure_remote(
            "mymega", "mega", username="--config=/etc/passwd", password="pass"
        )
        assert result["ok"] is False
        assert "Invalid" in result["msg"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_configure_remote_mega_validation_fails(self, mock_run, mock_exists, manager):
        """When MEGA lsd validation fails, remote is deleted and error returned."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # config create
            MagicMock(returncode=1, stdout="", stderr="login failed\n"),  # lsd check fails
            MagicMock(returncode=0, stdout="", stderr=""),  # config delete
        ]

        result = manager.configure_remote(
            "mymega", "mega", username="user@test.com", password="wrong"
        )
        assert result["ok"] is False


# ===========================================================================
# Standalone helpers
# ===========================================================================


class TestStandaloneHelpers:
    @patch("subprocess.run")
    def test_get_existing_remotes(self, mock_run):
        """get_existing_remotes parses rclone listremotes output."""
        mock_run.return_value = MagicMock(returncode=0, stdout="gdrive:\nonedrive:\nmega:\n")
        remotes = get_existing_remotes()
        assert remotes == ["gdrive", "onedrive", "mega"]

    @patch("subprocess.run")
    def test_get_existing_remotes_empty(self, mock_run):
        """get_existing_remotes returns empty list on failure."""
        mock_run.side_effect = Exception("no rclone")
        remotes = get_existing_remotes()
        assert remotes == []

    @patch("cloudhop.transfer.get_existing_remotes", return_value=["gdrive", "mega"])
    def test_remote_exists_true(self, mock_remotes):
        assert remote_exists("gdrive") is True

    @patch("cloudhop.transfer.get_existing_remotes", return_value=["gdrive", "mega"])
    def test_remote_exists_false(self, mock_remotes):
        assert remote_exists("dropbox") is False


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_default_state_keys(self, manager):
        """_default_state returns all required keys."""
        ds = manager._default_state()
        required = [
            "sessions",
            "original_total_bytes",
            "original_total_files",
            "last_elapsed_sec",
            "last_log_offset",
            "cumulative_transferred_bytes",
            "cumulative_files_done",
            "cumulative_elapsed_sec",
            "all_file_types",
            "total_copied_count",
            "speed_samples",
        ]
        for key in required:
            assert key in ds

    def test_cm_dir_created(self, tmp_path):
        """TransferManager creates cm_dir if it doesn't exist."""
        new_dir = str(tmp_path / "new_cm_dir")
        assert not os.path.exists(new_dir)
        TransferManager(cm_dir=new_dir)
        assert os.path.isdir(new_dir)

    def test_thread_safety_state_lock(self, manager):
        """state_lock is an RLock and transfer_lock is a Lock."""
        assert isinstance(manager.state_lock, type(threading.RLock()))
        assert isinstance(manager.transfer_lock, type(threading.Lock()))

    def test_parse_current_empty_log(self, tmp_path):
        """parse_current handles an empty log file."""
        m = TransferManager(cm_dir=str(tmp_path))
        m.log_file = str(tmp_path / "empty.log")
        with open(m.log_file, "w") as f:
            f.write("")
        m.rclone_pid = None

        result = m.parse_current()
        # Should not crash, should have basic structure
        assert result["finished"] is True
        assert result.get("errors", 0) == 0

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_start_transfer_strips_secrets_from_saved_cmd(self, mock_exists, mock_popen, manager):
        """start_transfer does not persist credential-containing flags."""
        mock_proc = MagicMock()
        mock_proc.pid = 1111
        mock_popen.return_value = mock_proc

        manager.start_transfer(
            {
                "source": "/tmp/a",
                "dest": "/tmp/b",
                "source_type": "local",
                "dest_type": "local",
            }
        )

        saved_cmd = manager.state.get("rclone_cmd", [])
        # No arg should contain password/secret/token etc
        for arg in saved_cmd:
            assert "password" not in arg.lower()
            assert "secret" not in arg.lower()
            assert "token" not in arg.lower()

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_start_transfer_transfers_clamped(self, mock_exists, mock_popen, manager):
        """Transfers count is clamped to valid range."""
        mock_proc = MagicMock()
        mock_proc.pid = 2222
        mock_popen.return_value = mock_proc

        # transfers=999 is out of range (MAX_TRANSFERS=64), should default to 8
        manager.start_transfer(
            {
                "source": "/tmp/a",
                "dest": "/tmp/b",
                "source_type": "local",
                "dest_type": "local",
                "transfers": "999",
            }
        )
        cmd = mock_popen.call_args[0][0]
        assert "--transfers=8" in cmd

    def test_scan_full_log_copied_files_without_extension(self, tmp_path):
        """Files without extensions are tracked as 'other'."""
        m = TransferManager(cm_dir=str(tmp_path))
        m.log_file = str(tmp_path / "test.log")
        with open(m.log_file, "w") as f:
            f.write("2025/06/10 10:00:00 INFO  : Makefile: Copied (new)\n")
            f.write("Transferred:   \t  100 MiB / 1.000 GiB, 10%, 50.000 MiB/s, ETA 60s\n")
            f.write("Transferred:            1 / 10, 10%\n")
            f.write("Errors:                 0\n")
            f.write("Elapsed time:      30.0s\n")

        m.scan_full_log()
        assert m.state["all_file_types"].get("other", 0) >= 1

    @patch("cloudhop.transfer.platform.system", return_value="Linux")
    def test_resume_loads_cmd_from_state(self, mock_sys, manager):
        """resume() loads rclone_cmd from state if not in memory."""
        manager.rclone_cmd = []
        manager.state["rclone_cmd"] = ["rclone", "copy", "a:", "b:"]

        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.pid = 7777
            mock_popen.return_value = mock_proc

            result = manager.resume()
            assert result["ok"] is True
            assert manager.rclone_pid == 7777


# ===========================================================================
# Verify Transfer
# ===========================================================================


class TestVerifyTransfer:
    def test_verify_no_command(self, manager):
        """verify_transfer returns error when no command is configured."""
        manager.rclone_cmd = []
        result = manager.verify_transfer()
        assert result["ok"] is False
        assert "No transfer" in result["msg"]

    @patch("os.kill")
    @patch("os.waitpid", return_value=(0, 0))
    def test_verify_while_running(self, mock_waitpid, mock_kill, manager):
        """verify_transfer returns error when rclone is still running."""
        manager.rclone_pid = 1234
        manager.rclone_cmd = ["rclone", "copy", "src:", "dst:"]
        result = manager.verify_transfer()
        assert result["ok"] is False
        assert "still running" in result["msg"]

    @patch("subprocess.run")
    def test_verify_perfect(self, mock_run, manager):
        """verify_transfer returns perfect when rclone check passes."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        manager.rclone_cmd = ["rclone", "copy", "src:", "dst:", "--exclude=Trash/**"]
        manager.rclone_pid = None
        result = manager.verify_transfer()
        assert result["ok"] is True
        assert result["status"] == "perfect"
        # Verify exclude flag was passed to check command
        cmd = mock_run.call_args[0][0]
        assert "--exclude=Trash/**" in cmd
        assert cmd[0] == "rclone"
        assert cmd[1] == "check"

    @patch("subprocess.run")
    def test_verify_differences(self, mock_run, manager):
        """verify_transfer reports differences when files are missing."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="ERROR : file.txt: not in destination\n",
        )
        manager.rclone_cmd = ["rclone", "copy", "src:", "dst:"]
        manager.rclone_pid = None
        result = manager.verify_transfer()
        assert result["ok"] is True
        assert result["status"] == "differences"
        assert result["differences"] == 1

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="rclone", timeout=600))
    def test_verify_timeout(self, mock_run, manager):
        """verify_transfer handles timeout."""
        manager.rclone_cmd = ["rclone", "copy", "src:", "dst:"]
        manager.rclone_pid = None
        result = manager.verify_transfer()
        assert result["ok"] is False
        assert "timed out" in result["msg"]


# ===========================================================================
# Battery Check
# ===========================================================================


class TestBatteryCheck:
    @patch("platform.system", return_value="Linux")
    def test_not_mac(self, mock_sys, manager):
        """_is_on_battery returns False on non-Mac."""
        assert manager._is_on_battery() is False

    @patch("platform.system", return_value="Darwin")
    @patch("subprocess.run")
    def test_on_ac(self, mock_run, mock_sys, manager):
        """_is_on_battery returns False on AC power."""
        mock_run.return_value = MagicMock(stdout="'AC Power'")
        assert manager._is_on_battery() is False

    @patch("platform.system", return_value="Darwin")
    @patch("subprocess.run")
    def test_on_battery(self, mock_run, mock_sys, manager):
        """_is_on_battery returns True on battery."""
        mock_run.return_value = MagicMock(stdout="'Battery Power'")
        assert manager._is_on_battery() is True


# ===========================================================================
# Crash Backoff
# ===========================================================================


class TestCrashBackoff:
    @patch("cloudhop.transfer.platform.system", return_value="Linux")
    @patch("subprocess.Popen")
    def test_backoff_after_3_crashes(self, mock_popen, mock_sys, manager):
        """resume returns error after 3 rapid failures."""
        mock_proc = MagicMock()
        mock_proc.pid = 1111
        mock_popen.return_value = mock_proc
        manager.rclone_cmd = ["rclone", "copy", "a:", "b:"]

        manager._crash_times = [time.time() - 10, time.time() - 5, time.time() - 1]
        result = manager.resume()
        assert result["ok"] is False
        assert "keeps failing" in result["msg"]

    @patch("cloudhop.transfer.platform.system", return_value="Linux")
    @patch("subprocess.Popen")
    def test_backoff_resets_after_5min(self, mock_popen, mock_sys, manager):
        """resume works again after 5 minutes of backoff."""
        mock_proc = MagicMock()
        mock_proc.pid = 2222
        mock_popen.return_value = mock_proc
        manager.rclone_cmd = ["rclone", "copy", "a:", "b:"]

        manager._crash_times = [time.time() - 400, time.time() - 350, time.time() - 310]
        result = manager.resume()
        assert result["ok"] is True


# ===========================================================================
# Transfer Queue
# ===========================================================================


class TestTransferQueue:
    def test_queue_add(self, manager):
        """queue_add adds an entry with queue_id."""
        result = manager.queue_add({"source": "gdrive:", "dest": "onedrive:"})
        assert result["ok"] is True
        assert "queue_id" in result
        assert len(manager.queue) == 1
        assert manager.queue[0]["status"] == "waiting"
        assert "added_at" in manager.queue[0]

    def test_queue_add_missing_source(self, manager):
        """queue_add rejects missing source."""
        result = manager.queue_add({"source": "", "dest": "onedrive:"})
        assert result["ok"] is False

    def test_queue_add_validates_input(self, manager):
        """queue_add rejects flag injection."""
        result = manager.queue_add({"source": "--config=/etc/passwd", "dest": "x:"})
        assert result["ok"] is False

    def test_queue_list(self, manager):
        """queue_list returns current queue."""
        manager.queue_add({"source": "a:", "dest": "b:"})
        manager.queue_add({"source": "c:", "dest": "d:"})
        items = manager.queue_list()
        assert len(items) == 2
        assert items[0]["config"]["source"] == "a:"

    def test_queue_remove(self, manager):
        """queue_remove removes by queue_id."""
        r1 = manager.queue_add({"source": "a:", "dest": "b:"})
        manager.queue_add({"source": "c:", "dest": "d:"})
        assert manager.queue_remove(r1["queue_id"]) is True
        assert len(manager.queue) == 1
        assert manager.queue[0]["config"]["source"] == "c:"

    def test_queue_remove_nonexistent(self, manager):
        """queue_remove returns False for unknown queue_id."""
        assert manager.queue_remove("nonexistent") is False

    def test_queue_persists_to_disk(self, manager):
        """Queue is saved and loaded from disk."""
        manager.queue_add({"source": "a:", "dest": "b:"})
        # Reload
        manager._load_queue()
        assert len(manager.queue) == 1
        assert manager.queue[0]["config"]["source"] == "a:"

    def test_queue_reorder(self, manager):
        """queue_reorder moves an item to a new position."""
        r1 = manager.queue_add({"source": "a:", "dest": "b:"})
        r2 = manager.queue_add({"source": "c:", "dest": "d:"})
        r3 = manager.queue_add({"source": "e:", "dest": "f:"})
        # Move third item to position 0
        assert manager.queue_reorder(r3["queue_id"], 0) is True
        assert manager.queue[0]["queue_id"] == r3["queue_id"]
        assert manager.queue[1]["queue_id"] == r1["queue_id"]
        assert manager.queue[2]["queue_id"] == r2["queue_id"]

    def test_queue_process_marks_completed(self, manager):
        """queue_process_next marks active items as completed."""
        manager.queue = [
            {"queue_id": "aaa", "status": "active", "config": {"source": "a:", "dest": "b:"}},
            {"queue_id": "bbb", "status": "waiting", "config": {"source": "c:", "dest": "d:"}},
        ]
        # Process should mark first as completed, try to start second
        manager.queue_process_next()
        assert manager.queue[0]["status"] == "completed"


# ===========================================================================
# Queue Processing
# ===========================================================================


class TestQueueProcessing:
    def test_queue_process_next_empty_queue(self, manager):
        """queue_process_next returns error when the queue is empty."""
        manager.queue = []
        result = manager.queue_process_next()
        assert result["ok"] is False
        assert "empty" in result["msg"].lower()

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_queue_process_next_starts_transfer(self, mock_exists, mock_popen, manager):
        """queue_process_next starts the next waiting transfer."""
        mock_proc = MagicMock()
        mock_proc.pid = 8888
        mock_popen.return_value = mock_proc

        manager.queue = [
            {
                "queue_id": "test123456789abc",
                "status": "waiting",
                "added_at": "2025-01-01T00:00:00",
                "config": {
                    "source": "/tmp/a",
                    "dest": "/tmp/b",
                    "source_type": "local",
                    "dest_type": "local",
                },
            }
        ]
        result = manager.queue_process_next()
        assert result["ok"] is True
        assert manager.queue[0]["status"] == "active"

    def test_background_scanner_is_daemon(self, manager):
        """background_scanner thread can be set as daemon."""
        t = threading.Thread(target=manager.background_scanner, daemon=True)
        assert t.daemon is True
        # Do NOT start the thread (it loops forever)

    @patch("time.sleep", side_effect=StopIteration)
    def test_scanner_runs_periodically(self, mock_sleep, manager):
        """background_scanner calls scan_full_log at least once per loop."""
        manager.scan_full_log = MagicMock()
        manager._check_schedule = MagicMock()
        manager._check_battery = MagicMock()
        manager.queue_process_next = MagicMock()

        try:
            manager.background_scanner()
        except StopIteration:
            pass

        manager.scan_full_log.assert_called()


# ===========================================================================
# OneDrive Detection
# ===========================================================================


class TestOneDriveDetection:
    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_onedrive_with_drive_id_present(self, mock_run, mock_exists, manager):
        """When drive_id is already in config dump, rclone backend drives is not called."""
        mock_run.side_effect = [
            # Call 1: rclone config create
            MagicMock(returncode=0, stderr="", stdout=""),
            # Call 2: rclone config dump (drive_id already present)
            MagicMock(
                returncode=0,
                stderr="",
                stdout=json.dumps({"od": {"type": "onedrive", "drive_id": "existing123"}}),
            ),
        ]
        result = manager.configure_remote("od", "onedrive")
        assert result["ok"] is True
        # Should NOT have called "rclone backend drives"
        for call in mock_run.call_args_list:
            cmd = call[0][0]
            assert "backend" not in cmd

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_onedrive_auto_detect_drive_id(self, mock_run, mock_exists, manager):
        """OneDrive auto-detects drive_id when not present in config dump."""
        mock_run.side_effect = [
            # Call 1: rclone config create
            MagicMock(returncode=0, stderr="", stdout=""),
            # Call 2: rclone config dump (no drive_id)
            MagicMock(
                returncode=0,
                stderr="",
                stdout=json.dumps({"od": {"type": "onedrive"}}),
            ),
            # Call 3: rclone backend drives od:
            MagicMock(
                returncode=0,
                stderr="",
                stdout=json.dumps([{"id": "abc123", "driveType": "personal"}]),
            ),
            # Call 4: rclone config update od drive_id=abc123 drive_type=personal
            MagicMock(returncode=0, stderr="", stdout=""),
            # Call 5: rclone lsd od: (validation)
            MagicMock(returncode=0, stderr="", stdout=""),
        ]
        result = manager.configure_remote("od", "onedrive")
        assert result["ok"] is True
        # Verify that config update was called with drive_id=abc123
        update_calls = [
            c for c in mock_run.call_args_list if "config" in c[0][0] and "update" in c[0][0]
        ]
        assert len(update_calls) >= 1
        update_cmd = update_calls[0][0][0]
        assert "drive_id=abc123" in update_cmd

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_onedrive_malformed_drives_output(self, mock_run, mock_exists, manager):
        """Malformed rclone backend drives output is handled gracefully."""
        mock_run.side_effect = [
            # Call 1: rclone config create
            MagicMock(returncode=0, stderr="", stdout=""),
            # Call 2: rclone config dump (no drive_id)
            MagicMock(
                returncode=0,
                stderr="",
                stdout=json.dumps({"od": {"type": "onedrive"}}),
            ),
            # Call 3: rclone backend drives od: (malformed output)
            MagicMock(returncode=0, stderr="", stdout="invalid json"),
        ]
        result = manager.configure_remote("od", "onedrive")
        assert result["ok"] is True


# ===========================================================================
# System file exclusion (Item 3)
# ===========================================================================


class TestSystemFileExclusion:
    @patch("os.path.exists", return_value=True)
    @patch("subprocess.Popen")
    def test_start_transfer_excludes_system_files(self, mock_popen, mock_exists, manager):
        """.DS_Store, Thumbs.db, desktop.ini, .gitkeep are excluded from transfer."""
        from cloudhop.utils import SYSTEM_EXCLUDES

        mock_popen.return_value = MagicMock(pid=123)
        result = manager.start_transfer(
            {
                "source": "/tmp/src",
                "dest": "/tmp/dst",
                "source_type": "local",
                "dest_type": "local",
            }
        )
        assert result.get("ok") is True
        cmd = manager.rclone_cmd
        for excl in SYSTEM_EXCLUDES:
            assert f"--exclude={excl}" in cmd, f"Missing --exclude={excl} in rclone cmd"

    @patch("os.path.exists", return_value=True)
    @patch("subprocess.Popen")
    def test_ds_store_not_in_transfer_command(self, mock_popen, mock_exists, manager):
        """Specifically verify .DS_Store is excluded (regression test)."""
        mock_popen.return_value = MagicMock(pid=123)
        manager.start_transfer(
            {
                "source": "/tmp/src",
                "dest": "/tmp/dst",
                "source_type": "local",
                "dest_type": "local",
            }
        )
        assert "--exclude=.DS_Store" in manager.rclone_cmd
        assert "--exclude=Thumbs.db" in manager.rclone_cmd
        assert "--exclude=desktop.ini" in manager.rclone_cmd
        assert "--exclude=.gitkeep" in manager.rclone_cmd


# ===========================================================================
# Notification on transfer completion (Item 4)
# ===========================================================================


class TestCompletionNotification:
    def test_scanner_notifies_on_completion(self, manager):
        """background_scanner calls notify on successful transfer completion."""
        manager.rclone_cmd = ["rclone", "copy", "/tmp/a", "/tmp/b"]
        manager._completion_notified = False

        with (
            patch.object(manager, "is_rclone_running", return_value=False),
            patch.object(
                manager,
                "parse_current",
                return_value={
                    "global_files_done": 42,
                    "global_transferred": "1.5 GiB",
                    "global_pct": 100,
                    "global_elapsed": "5m30s",
                    "error_messages": [],
                },
            ),
            patch("cloudhop.transfer.notify") as mock_notify,
            patch.object(manager, "scan_full_log"),
            patch.object(manager, "_check_schedule"),
            patch.object(manager, "_check_battery"),
            patch("cloudhop.transfer.time.sleep", side_effect=StopIteration),
        ):
            try:
                manager.background_scanner()
            except StopIteration:
                pass

            mock_notify.assert_called_once()
            call_args = mock_notify.call_args[0]
            assert call_args[0] == "CloudHop: Transfer Complete"
            assert "42" in call_args[1]
            assert "1.5 GiB" in call_args[1]

    def test_scanner_notifies_on_failure(self, manager):
        """background_scanner calls notify on failed transfer."""
        manager.rclone_cmd = ["rclone", "copy", "/tmp/a", "/tmp/b"]
        manager._completion_notified = False

        with (
            patch.object(manager, "is_rclone_running", return_value=False),
            patch.object(
                manager,
                "parse_current",
                return_value={
                    "global_files_done": 5,
                    "global_transferred": "100 MiB",
                    "global_pct": 10,
                    "global_elapsed": "1m",
                    "error_messages": ["connection timeout"],
                },
            ),
            patch("cloudhop.transfer.notify") as mock_notify,
            patch.object(manager, "scan_full_log"),
            patch.object(manager, "_check_schedule"),
            patch.object(manager, "_check_battery"),
            patch("cloudhop.transfer.time.sleep", side_effect=StopIteration),
        ):
            try:
                manager.background_scanner()
            except StopIteration:
                pass

            mock_notify.assert_called_once()
            call_args = mock_notify.call_args[0]
            assert call_args[0] == "CloudHop: Transfer Failed"
            assert "connection timeout" in call_args[1]

    def test_scanner_does_not_notify_twice(self, manager):
        """Once notified, background_scanner should not notify again."""
        manager.rclone_cmd = ["rclone", "copy", "/tmp/a", "/tmp/b"]
        manager._completion_notified = True  # Already notified

        with (
            patch.object(manager, "is_rclone_running", return_value=False),
            patch.object(manager, "parse_current") as mock_parse,
            patch("cloudhop.transfer.notify") as mock_notify,
            patch.object(manager, "scan_full_log"),
            patch.object(manager, "_check_schedule"),
            patch.object(manager, "_check_battery"),
            patch("cloudhop.transfer.time.sleep", side_effect=StopIteration),
        ):
            try:
                manager.background_scanner()
            except StopIteration:
                pass

            mock_notify.assert_not_called()
            mock_parse.assert_not_called()


# ===========================================================================
# B1: ETA Smoothing (Exponential Moving Average)
# ===========================================================================


class TestETASmoothing:
    def test_ema_first_measurement_uses_raw_speed(self, manager_with_log):
        """First speed measurement should set smoothed_speed = raw speed."""
        m = manager_with_log
        m._speed_ema = 0.0  # No history
        m.rclone_pid = 99999
        with patch("os.waitpid", return_value=(0, 0)), patch("os.kill"):
            result = m.parse_current()
        # After parsing FAKE_LOG, EMA should be set (not zero)
        assert m._speed_ema > 0
        assert "smoothed_speed" in result

    def test_ema_smoothing_reduces_fluctuations(self, tmp_path):
        """EMA should smooth out speed spikes - verify with fluctuating data."""
        m = TransferManager(cm_dir=str(tmp_path))
        m._ema_alpha = 0.3

        # Simulate: feed a series of fluctuating speeds
        raw_speeds = [10.0, 100.0, 5.0, 80.0, 8.0]  # MB/s, wildly varying
        smoothed_values = []
        for speed_mbs in raw_speeds:
            speed_bps = speed_mbs * 1024 * 1024
            if m._speed_ema == 0:
                m._speed_ema = speed_bps
            else:
                m._speed_ema = 0.3 * speed_bps + 0.7 * m._speed_ema
            smoothed_values.append(m._speed_ema / (1024 * 1024))

        # Smoothed values should have less variance than raw speeds
        raw_range = max(raw_speeds) - min(raw_speeds)
        smoothed_range = max(smoothed_values) - min(smoothed_values)
        assert smoothed_range < raw_range, "EMA should reduce fluctuation range"

    def test_ema_calculating_when_no_speed(self, tmp_path):
        """When no speed data available, smoothed_eta should be 'Calculating...'."""
        m = TransferManager(cm_dir=str(tmp_path))
        m.log_file = str(tmp_path / "empty.log")
        # Log with stats but no speed/ETA line
        with open(m.log_file, "w") as f:
            f.write(
                textwrap.dedent("""\
                2025/06/10 10:00:00 INFO  :
                Transferred:            5 / 100, 5%
                Errors:                 0
                Elapsed time:      30.5s
            """)
            )
        m.rclone_pid = 99999
        with patch("os.waitpid", return_value=(0, 0)), patch("os.kill"):
            result = m.parse_current()
        assert result.get("smoothed_eta") == "Calculating..."

    def test_ema_not_shown_when_finished(self, manager_with_log):
        """When transfer is finished, smoothed_eta should not be 'Calculating...'."""
        m = manager_with_log
        m.rclone_pid = None  # Simulate finished
        result = m.parse_current()
        assert result.get("smoothed_eta") != "Calculating..."

    def test_ema_reset_on_new_transfer(self, tmp_path):
        """_speed_ema should reset to 0 when starting a new transfer."""
        m = TransferManager(cm_dir=str(tmp_path))
        m._speed_ema = 50000.0  # Simulated leftover value
        body = {
            "source": str(tmp_path),
            "dest": str(tmp_path / "dest"),
            "source_type": "local",
            "dest_type": "local",
        }
        os.makedirs(tmp_path / "dest", exist_ok=True)
        with patch("subprocess.Popen", side_effect=OSError("test")):
            m.start_transfer(body)
        assert m._speed_ema == 0.0


# ===========================================================================
# B3: Proton Drive Rate Limit Auto-Throttle
# ===========================================================================


class TestRateLimitThrottle:
    def test_rate_limit_detection_with_429_errors(self, tmp_path):
        """429 errors in rclone log should be detected as rate limiting."""
        m = TransferManager(cm_dir=str(tmp_path))
        m.log_file = str(tmp_path / "test.log")
        log_content = "\n".join(
            [
                f"2025/06/10 10:00:{i:02d} ERROR : file{i}.txt: 429 Too Many Requests"
                for i in range(5)
            ]
        )
        with open(m.log_file, "w") as f:
            f.write(log_content)
        errors = m._parse_error_messages()
        assert m._rate_limited is True
        assert any("rate limit" in e.lower() or "429" in e for e in errors)

    def test_throttle_triggers_on_3_errors_in_60s(self, tmp_path):
        """When 3+ rate limit errors occur in 60s, transfers should be reduced."""
        m = TransferManager(cm_dir=str(tmp_path))
        m.rclone_cmd = ["rclone", "copy", "/src", "/dst", "--transfers=8"]
        m._original_transfers = 8
        m._current_transfers = 8
        m.rclone_pid = 99999

        # Simulate 3 rate limit timestamps within 60 seconds
        now = time.time()
        m._rate_limit_timestamps = [now - 30, now - 20, now - 10]

        with (
            patch.object(m, "is_rclone_running", return_value=True),
            patch.object(m, "_set_transfers_rc") as mock_rc,
        ):
            m._apply_rate_limit_throttle()

        assert m._current_transfers == 4  # 8 // 2 = 4
        assert m._throttle_active is True
        mock_rc.assert_called_once_with(4)

    def test_throttle_minimum_is_1(self, tmp_path):
        """Throttling should never go below 1 transfer."""
        m = TransferManager(cm_dir=str(tmp_path))
        m.rclone_cmd = ["rclone", "copy", "/src", "/dst", "--transfers=2"]
        m._original_transfers = 2
        m._current_transfers = 2

        now = time.time()
        m._rate_limit_timestamps = [now - 10, now - 5, now - 1]

        with (
            patch.object(m, "is_rclone_running", return_value=True),
            patch.object(m, "_set_transfers_rc"),
        ):
            m._apply_rate_limit_throttle()
            assert m._current_transfers == 1

            # Should not throttle further below 1
            m._apply_rate_limit_throttle()
            assert m._current_transfers == 1

    def test_gradual_restore_after_5_minutes(self, tmp_path):
        """After 5 minutes of no rate limiting, transfers should increment by 1."""
        m = TransferManager(cm_dir=str(tmp_path))
        m._original_transfers = 8
        m._current_transfers = 2
        m._throttle_active = True
        m._last_rate_limit_time = time.time() - 301  # 5+ minutes ago

        with (
            patch.object(m, "is_rclone_running", return_value=True),
            patch.object(m, "_set_transfers_rc") as mock_rc,
        ):
            m._restore_transfers_gradual()

        assert m._current_transfers == 3  # 2 + 1
        assert m._throttle_active is True  # Still active (not back to 8 yet)
        mock_rc.assert_called_once_with(3)

    def test_throttle_deactivates_when_fully_restored(self, tmp_path):
        """Throttle flag should clear when transfers reach original value."""
        m = TransferManager(cm_dir=str(tmp_path))
        m._original_transfers = 3
        m._current_transfers = 2
        m._throttle_active = True
        m._last_rate_limit_time = time.time() - 301

        with (
            patch.object(m, "is_rclone_running", return_value=True),
            patch.object(m, "_set_transfers_rc"),
        ):
            m._restore_transfers_gradual()

        assert m._current_transfers == 3
        assert m._throttle_active is False

    def test_dashboard_message_when_throttled(self, tmp_path):
        """Dashboard should show 'Speed reduced' message when throttle is active."""
        m = TransferManager(cm_dir=str(tmp_path))
        m.log_file = str(tmp_path / "test.log")
        m._throttle_active = True
        log_content = "2025/06/10 10:00:00 ERROR : file.txt: 429 Too Many Requests\n"
        with open(m.log_file, "w") as f:
            f.write(log_content)
        errors = m._parse_error_messages()
        assert any("speed reduced" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Sync mode tests
# ---------------------------------------------------------------------------


class TestSyncMode:
    """Tests for sync/bisync transfer mode support."""

    @pytest.fixture
    def manager(self, tmp_path):
        m = TransferManager(cm_dir=str(tmp_path))
        return m

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_sync_mode_builds_correct_command(self, mock_exists, mock_popen, manager):
        """mode='sync' generates 'rclone sync' not 'rclone copy'."""
        mock_proc = MagicMock()
        mock_proc.pid = 7001
        mock_popen.return_value = mock_proc

        result = manager.start_transfer(
            {
                "source": "/local/src",
                "dest": "gdrive:dst",
                "source_type": "local",
                "dest_type": "drive",
                "mode": "sync",
            }
        )
        assert result["ok"] is True
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "rclone"
        assert cmd[1] == "sync"

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_bisync_mode_builds_correct_command(self, mock_exists, mock_popen, manager):
        """mode='bisync' generates 'rclone bisync'."""
        mock_proc = MagicMock()
        mock_proc.pid = 7002
        mock_popen.return_value = mock_proc

        result = manager.start_transfer(
            {
                "source": "/local/src",
                "dest": "gdrive:dst",
                "source_type": "local",
                "dest_type": "drive",
                "mode": "bisync",
            }
        )
        assert result["ok"] is True
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "rclone"
        assert cmd[1] == "bisync"

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_copy_mode_default(self, mock_exists, mock_popen, manager):
        """Missing mode defaults to 'copy' (backward compatible)."""
        mock_proc = MagicMock()
        mock_proc.pid = 7003
        mock_popen.return_value = mock_proc

        result = manager.start_transfer(
            {
                "source": "/local/src",
                "dest": "gdrive:dst",
                "source_type": "local",
                "dest_type": "drive",
            }
        )
        assert result["ok"] is True
        cmd = mock_popen.call_args[0][0]
        assert cmd[1] == "copy"

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_sync_warning_logged(self, mock_exists, mock_popen, manager, caplog):
        """mode='sync' logs a WARNING about deletion."""
        mock_proc = MagicMock()
        mock_proc.pid = 7004
        mock_popen.return_value = mock_proc

        with caplog.at_level(logging.WARNING, logger="cloudhop.transfer"):
            manager.start_transfer(
                {
                    "source": "/local/src",
                    "dest": "gdrive:dst",
                    "source_type": "local",
                    "dest_type": "drive",
                    "mode": "sync",
                }
            )
        assert any("DELETE" in r.message for r in caplog.records)

    @patch("subprocess.Popen")
    def test_bisync_first_run_resync_flag(self, mock_popen, manager):
        """First bisync run includes --resync flag."""
        mock_proc = MagicMock()
        mock_proc.pid = 7005
        mock_popen.return_value = mock_proc

        # Ensure the bisync_initialized marker does not exist
        marker = os.path.join(manager.cm_dir, "bisync_initialized")
        if os.path.exists(marker):
            os.remove(marker)

        # Use real os.path.exists so bisync marker check works; source is local so create it
        src = os.path.join(manager.cm_dir, "fakesrc")
        os.makedirs(src, exist_ok=True)

        result = manager.start_transfer(
            {
                "source": src,
                "dest": "gdrive:dst",
                "source_type": "local",
                "dest_type": "drive",
                "mode": "bisync",
            }
        )
        assert result["ok"] is True
        cmd = mock_popen.call_args[0][0]
        assert "--resync" in cmd
        # Marker should now exist
        assert os.path.exists(marker)

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_mode_persisted_in_state(self, mock_exists, mock_popen, manager):
        """Transfer mode is saved to and restored from state file."""
        mock_proc = MagicMock()
        mock_proc.pid = 7006
        mock_popen.return_value = mock_proc

        manager.start_transfer(
            {
                "source": "/local/src",
                "dest": "gdrive:dst",
                "source_type": "local",
                "dest_type": "drive",
                "mode": "sync",
            }
        )
        assert manager.state.get("mode") == "sync"

        # Reload state from disk and verify
        loaded = manager._load_state()
        assert loaded.get("mode") == "sync"

    def test_mode_in_queue(self, manager):
        """Queue items preserve the transfer mode."""
        result = manager.queue_add(
            {
                "source": "gdrive:src",
                "dest": "onedrive:dst",
                "source_type": "drive",
                "dest_type": "onedrive",
                "mode": "bisync",
            }
        )
        assert result["ok"] is True
        queue = manager.queue_list()
        assert len(queue) == 1
        assert queue[0]["config"]["mode"] == "bisync"


# ===========================================================================
# F103 – Successful resumes must not trigger crash backoff
# ===========================================================================


class TestCrashBackoffSuccessNoCount:
    @patch("cloudhop.transfer.platform.system", return_value="Linux")
    @patch("subprocess.Popen")
    def test_successful_resumes_do_not_trigger_backoff(self, mock_popen, mock_sys, manager):
        """4 rapid successful resumes must NOT trigger crash backoff."""
        mock_proc = MagicMock()
        mock_proc.pid = 9999
        mock_popen.return_value = mock_proc
        manager.rclone_cmd = ["rclone", "copy", "a:", "b:"]

        for _ in range(4):
            # Reset so is_rclone_running() returns False
            manager.transfer_active = False
            manager.rclone_pid = None
            manager._rclone_proc = None
            result = manager.resume()
            assert result["ok"] is True, f"Expected ok=True, got: {result}"


# ===========================================================================
# F220 – --config must NOT be in the rclone flag allowlist
# ===========================================================================


class TestConfigFlagRejected:
    def test_config_flag_rejected(self):
        """--config flag must be rejected by validate_rclone_cmd."""
        assert (
            validate_rclone_cmd(["rclone", "copy", "src:", "dst:", "--config=/tmp/evil.conf"])
            is False
        )


# ===========================================================================
# F221 – Subcommand validation
# ===========================================================================


class TestSubcommandValidation:
    def test_purge_rejected(self):
        assert validate_rclone_cmd(["rclone", "purge", "remote:"]) is False

    def test_delete_rejected(self):
        assert validate_rclone_cmd(["rclone", "delete", "remote:"]) is False

    def test_copy_allowed(self):
        assert validate_rclone_cmd(["rclone", "copy", "src:", "dst:"]) is True

    def test_sync_allowed(self):
        assert validate_rclone_cmd(["rclone", "sync", "src:", "dst:"]) is True
