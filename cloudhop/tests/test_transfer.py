"""Comprehensive tests for cloudhop.transfer.TransferManager."""

import json
import os
import signal
import tempfile
import textwrap
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

from cloudhop.transfer import TransferManager, remote_exists, get_existing_remotes


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

    def test_set_transfer_paths_deterministic(self, manager):
        """Same source/dest always produce the same paths."""
        manager.set_transfer_paths("mega:stuff", "/tmp/local")
        log1 = manager.log_file
        state1 = manager.state_file

        manager.set_transfer_paths("mega:stuff", "/tmp/local")
        assert manager.log_file == log1
        assert manager.state_file == state1


# ===========================================================================
# Transfer Control (is_rclone_running, pause, resume, start_transfer)
# ===========================================================================


class TestTransferControl:

    def test_is_rclone_running_no_pid(self, manager):
        """Returns False when no pid is tracked."""
        manager.rclone_pid = None
        assert manager.is_rclone_running() is False

    @patch("os.waitpid", return_value=(0, 0))
    def test_is_rclone_running_with_pid_alive(self, mock_waitpid, manager):
        """Returns True when os.waitpid says the process is still running."""
        manager.rclone_pid = 12345
        assert manager.is_rclone_running() is True
        mock_waitpid.assert_called_once_with(12345, os.WNOHANG)

    @patch("os.waitpid", return_value=(12345, 0))
    def test_is_rclone_running_with_pid_exited(self, mock_waitpid, manager):
        """Returns False and clears pid when process has exited."""
        manager.rclone_pid = 12345
        assert manager.is_rclone_running() is False
        assert manager.rclone_pid is None

    @patch("os.waitpid", side_effect=ChildProcessError)
    @patch("os.kill")
    def test_is_rclone_running_not_child_but_alive(self, mock_kill, mock_waitpid, manager):
        """Falls back to kill(0) when not our child; returns True if alive."""
        manager.rclone_pid = 99999
        assert manager.is_rclone_running() is True
        mock_kill.assert_called_once_with(99999, 0)

    @patch("os.waitpid", side_effect=ChildProcessError)
    @patch("os.kill", side_effect=ProcessLookupError)
    def test_is_rclone_running_not_child_and_dead(self, mock_kill, mock_waitpid, manager):
        """Falls back to kill(0); returns False if process is gone."""
        manager.rclone_pid = 99999
        assert manager.is_rclone_running() is False
        assert manager.rclone_pid is None

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

    def test_pause_no_process(self, manager):
        """pause() returns error when no process is tracked."""
        manager.rclone_pid = None
        result = manager.pause()
        assert result["ok"] is False
        assert "No tracked" in result["msg"]

    @patch("os.kill", side_effect=ProcessLookupError)
    @patch("time.sleep")
    def test_pause_process_already_gone(self, mock_sleep, mock_kill, manager):
        """pause() handles the case where the process already exited."""
        manager.rclone_pid = 7777
        result = manager.pause()
        assert result["ok"] is False
        assert "not found" in result["msg"]

    @patch("subprocess.Popen")
    def test_resume_starts_process(self, mock_popen, manager):
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

    @patch("os.waitpid", return_value=(0, 0))
    def test_resume_already_running(self, mock_waitpid, manager):
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
        result = manager.start_transfer({
            "source": "--config=/etc/passwd",
            "dest": "/tmp/safe",
        })
        assert result["ok"] is False
        assert "Invalid" in result["msg"]

        result = manager.start_transfer({
            "source": "/tmp/safe",
            "dest": "--some-flag",
        })
        assert result["ok"] is False

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_start_transfer_builds_command(self, mock_exists, mock_popen, manager):
        """start_transfer builds a proper rclone command."""
        mock_proc = MagicMock()
        mock_proc.pid = 4444
        mock_popen.return_value = mock_proc

        result = manager.start_transfer({
            "source": "/local/photos",
            "dest": "gdrive:backup",
            "source_type": "local",
            "dest_type": "drive",
            "transfers": "4",
            "excludes": ["node_modules"],
            "bw_limit": "10M",
            "checksum": True,
        })
        assert result["ok"] is True
        assert result["pid"] == 4444

        cmd = mock_popen.call_args[0][0]
        assert "rclone" == cmd[0]
        assert "copy" == cmd[1]
        assert "/local/photos" == cmd[2]
        assert "gdrive:backup" == cmd[3]
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

        manager.start_transfer({
            "source": "gdrive:src",
            "dest": "onedrive:dst",
            "source_type": "drive",
            "dest_type": "onedrive",
        })
        cmd = mock_popen.call_args[0][0]
        assert "--drive-chunk-size=256M" in cmd
        assert "--buffer-size=128M" in cmd

    @patch("os.waitpid", return_value=(0, 0))
    def test_start_transfer_lock_prevents_concurrent(self, mock_waitpid, manager):
        """start_transfer rejects a second transfer while one is running."""
        manager.transfer_active = True
        manager.rclone_pid = 1111

        result = manager.start_transfer({
            "source": "/tmp/a",
            "dest": "/tmp/b",
            "source_type": "local",
            "dest_type": "local",
        })
        assert result["ok"] is False
        assert "already running" in result["msg"]

    def test_start_transfer_rejects_invalid_excludes(self, manager):
        """start_transfer rejects exclude patterns with shell injection chars."""
        result = manager.start_transfer({
            "source": "/tmp/a",
            "dest": "/tmp/b",
            "source_type": "local",
            "dest_type": "local",
            "excludes": ["valid", "bad{pattern}"],
        })
        assert result["ok"] is False

    @patch("subprocess.Popen")
    @patch("os.path.exists", return_value=True)
    def test_start_transfer_invalid_transfers_count(self, mock_exists, mock_popen, manager):
        """Invalid transfers count falls back to 8."""
        mock_proc = MagicMock()
        mock_proc.pid = 6666
        mock_popen.return_value = mock_proc

        manager.start_transfer({
            "source": "/tmp/a",
            "dest": "/tmp/b",
            "source_type": "local",
            "dest_type": "local",
            "transfers": "not_a_number",
        })
        cmd = mock_popen.call_args[0][0]
        assert "--transfers=8" in cmd

    def test_start_transfer_nonexistent_local_source(self, manager):
        """start_transfer rejects a local source path that doesn't exist."""
        result = manager.start_transfer({
            "source": "/nonexistent/path/that/does/not/exist",
            "dest": "/tmp/b",
            "source_type": "local",
            "dest_type": "local",
        })
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

    @patch("os.waitpid", return_value=(0, 0))
    def test_parse_current_running_flag(self, mock_waitpid, manager_with_log):
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

        result, xfer_str, total_str, xfer_bytes, total_bytes, lines = (
            m._parse_tail_stats(tail)
        )

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
        """MEGA with credentials calls obscure then config create then lsd."""
        # First call: rclone obscure
        # Second call: rclone config create
        # Third call: rclone lsd (validation)
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="obscured_pass\n", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        result = manager.configure_remote(
            "mymega", "mega", username="user@example.com", password="secret"
        )
        assert result["ok"] is True

        # Verify obscure was called
        assert mock_run.call_args_list[0][0][0] == ["rclone", "obscure", "secret"]

        # Verify config create was called with env vars
        config_call = mock_run.call_args_list[1]
        assert config_call.kwargs.get("env") is not None
        env = config_call.kwargs["env"]
        assert env["RCLONE_CONFIG_MYMEGA_USER"] == "user@example.com"
        assert env["RCLONE_CONFIG_MYMEGA_PASS"] == "obscured_pass"

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    def test_configure_remote_s3_needs_credentials(self, mock_exists, manager):
        """S3 without credentials returns needs_credentials."""
        result = manager.configure_remote("mys3", "s3")
        assert result["ok"] is False
        assert result["needs_credentials"] is True
        assert "Access Key" in result["user_label"]

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    @patch("subprocess.run")
    def test_configure_remote_s3_env_vars(self, mock_run, mock_exists, manager):
        """S3 configuration sets ACCESS_KEY_ID and SECRET_ACCESS_KEY env vars."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # config create
            MagicMock(returncode=0, stdout="", stderr=""),  # lsd check
        ]

        result = manager.configure_remote(
            "mys3", "s3", username="AKIAXXXXXXX", password="secretkey123"
        )
        assert result["ok"] is True

        config_call = mock_run.call_args_list[0]
        env = config_call.kwargs["env"]
        assert env["RCLONE_CONFIG_MYS3_ACCESS_KEY_ID"] == "AKIAXXXXXXX"
        assert env["RCLONE_CONFIG_MYS3_SECRET_ACCESS_KEY"] == "secretkey123"

        # Verify provider=AWS is in the command
        cmd = config_call[0][0]
        assert "provider=AWS" in cmd

    @patch("cloudhop.transfer.remote_exists", return_value=False)
    def test_configure_remote_protondrive_needs_credentials(self, mock_exists, manager):
        """Proton Drive without credentials returns needs_credentials."""
        result = manager.configure_remote("myproton", "protondrive")
        assert result["ok"] is False
        assert result["needs_credentials"] is True
        assert "Username" in result["user_label"]

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
            MagicMock(returncode=0, stdout="obscured\n", stderr=""),  # obscure
            MagicMock(returncode=0, stdout="", stderr=""),            # config create
            MagicMock(returncode=1, stdout="", stderr="login failed\n"),  # lsd check fails
            MagicMock(returncode=0, stdout="", stderr=""),            # config delete
        ]

        result = manager.configure_remote(
            "mymega", "mega", username="user@test.com", password="wrong"
        )
        assert result["ok"] is False
        assert "credentials" in result["msg"].lower() or "password" in result["msg"].lower()


# ===========================================================================
# Standalone helpers
# ===========================================================================


class TestStandaloneHelpers:

    @patch("subprocess.run")
    def test_get_existing_remotes(self, mock_run):
        """get_existing_remotes parses rclone listremotes output."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="gdrive:\nonedrive:\nmega:\n"
        )
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
            "sessions", "original_total_bytes", "original_total_files",
            "last_elapsed_sec", "last_log_offset", "cumulative_transferred_bytes",
            "cumulative_files_done", "cumulative_elapsed_sec", "all_file_types",
            "total_copied_count", "speed_samples",
        ]
        for key in required:
            assert key in ds

    def test_cm_dir_created(self, tmp_path):
        """TransferManager creates cm_dir if it doesn't exist."""
        new_dir = str(tmp_path / "new_cm_dir")
        assert not os.path.exists(new_dir)
        m = TransferManager(cm_dir=new_dir)
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

        manager.start_transfer({
            "source": "/tmp/a",
            "dest": "/tmp/b",
            "source_type": "local",
            "dest_type": "local",
        })

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
        manager.start_transfer({
            "source": "/tmp/a",
            "dest": "/tmp/b",
            "source_type": "local",
            "dest_type": "local",
            "transfers": "999",
        })
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

    def test_resume_loads_cmd_from_state(self, manager):
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
