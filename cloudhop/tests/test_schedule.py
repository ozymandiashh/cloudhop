"""Tests for CloudHop scheduling features."""

from datetime import datetime
from unittest.mock import MagicMock, patch

from cloudhop.transfer import TransferManager


class TestScheduleWindow:
    def test_disabled_schedule_always_in_window(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        assert mgr.is_in_schedule_window() is True

    def test_overnight_window_inside_late(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "22:00",
            "end_time": "06:00",
            "days": [0, 1, 2, 3, 4, 5, 6],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 18, 23, 30)
            mock_dt.strptime = datetime.strptime
            assert mgr.is_in_schedule_window() is True

    def test_overnight_window_inside_early(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "22:00",
            "end_time": "06:00",
            "days": [0, 1, 2, 3, 4, 5, 6],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 19, 3, 0)
            mock_dt.strptime = datetime.strptime
            assert mgr.is_in_schedule_window() is True

    def test_overnight_window_outside(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "22:00",
            "end_time": "06:00",
            "days": [0, 1, 2, 3, 4, 5, 6],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 18, 14, 0)
            mock_dt.strptime = datetime.strptime
            assert mgr.is_in_schedule_window() is False

    def test_daytime_window(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "09:00",
            "end_time": "17:00",
            "days": [0, 1, 2, 3, 4],
            "bw_limit_in_window": "5M",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 18, 12, 0)
            mock_dt.strptime = datetime.strptime
            assert mgr.is_in_schedule_window() is True

    def test_wrong_day(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "09:00",
            "end_time": "17:00",
            "days": [0, 1, 2, 3, 4],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 21, 12, 0)  # Saturday
            mock_dt.strptime = datetime.strptime
            assert mgr.is_in_schedule_window() is False

    def test_overnight_friday_to_saturday_morning(self, tmp_path):
        """Friday 22:00-06:00 schedule should allow Saturday 03:00."""
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "22:00",
            "end_time": "06:00",
            "days": [0, 1, 2, 3, 4],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 21, 3, 0)  # Saturday 3AM
            mock_dt.strptime = datetime.strptime
            # Friday (day 4) is in allowed days, so Saturday early morning should be allowed
            assert mgr.is_in_schedule_window() is True

    def test_exact_start_time(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "22:00",
            "end_time": "06:00",
            "days": [0, 1, 2, 3, 4, 5, 6],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 18, 22, 0)
            mock_dt.strptime = datetime.strptime
            assert mgr.is_in_schedule_window() is True

    def test_exact_end_time_exclusive(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "22:00",
            "end_time": "06:00",
            "days": [0, 1, 2, 3, 4, 5, 6],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch("cloudhop.transfer.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 3, 19, 6, 0)
            mock_dt.strptime = datetime.strptime
            assert mgr.is_in_schedule_window() is False

    def test_schedule_default_state(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        sched = mgr.state.get("schedule", {})
        assert sched["enabled"] is False
        assert sched["start_time"] == "22:00"
        assert sched["end_time"] == "06:00"
        assert len(sched["days"]) == 7


class TestSetBandwidth:
    @patch("subprocess.run")
    def test_set_bandwidth_success(self, mock_run, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.rclone_pid = 1234
        mgr._rc_port = 12345
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(mgr, "is_rclone_running", return_value=True):
            result = mgr.set_bandwidth("10M")
            assert result["ok"] is True

    def test_set_bandwidth_not_running(self, tmp_path):
        mgr = TransferManager(cm_dir=str(tmp_path))
        result = mgr.set_bandwidth("10M")
        assert result["ok"] is False


class TestCheckScheduleTransitions:
    def test_no_spam_on_repeated_calls(self, tmp_path):
        """_check_schedule should not fire actions on repeated calls with same state."""
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["schedule"] = {
            "enabled": True,
            "start_time": "00:00",
            "end_time": "23:59",
            "days": [0, 1, 2, 3, 4, 5, 6],
            "bw_limit_in_window": "",
            "bw_limit_out_window": "0",
        }
        with patch.object(mgr, "is_in_schedule_window", return_value=True):
            with patch.object(mgr, "resume") as mock_resume:
                mgr._check_schedule()  # First call - sets state
                mgr._check_schedule()  # Second call - no transition
                mgr._check_schedule()  # Third call - no transition
                # resume should be called at most once (on first transition)
                assert mock_resume.call_count <= 1


# ===========================================================================
# Battery Check
# ===========================================================================


class TestBatteryCheck:
    def test_ac_power_no_pause(self, tmp_path):
        """On AC power, transfer should not be paused."""
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["pause_on_battery"] = True
        mgr._has_battery = True  # Force battery capability for CI (Linux/Windows)
        with patch.object(mgr, "_is_on_battery", return_value=False):
            with patch.object(mgr, "is_rclone_running", return_value=True):
                with patch.object(mgr, "pause") as mock_pause:
                    mgr._check_battery()
                    mock_pause.assert_not_called()

    def test_battery_below_threshold_pauses(self, tmp_path):
        """On battery power, running transfer should be paused."""
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["pause_on_battery"] = True
        mgr._has_battery = True  # Force battery capability for CI (Linux/Windows)
        with patch.object(mgr, "_is_on_battery", return_value=True):
            with patch.object(mgr, "is_rclone_running", return_value=True):
                with patch.object(mgr, "pause") as mock_pause:
                    mgr._check_battery()
                    mock_pause.assert_called_once()
        assert mgr.state.get("_battery_paused") is True

    def test_recovery_battery_to_ac_resumes(self, tmp_path):
        """When power goes from battery to AC, previously paused transfer resumes."""
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["pause_on_battery"] = True
        mgr.state["_battery_paused"] = True
        mgr._has_battery = True  # Force battery capability for CI (Linux/Windows)
        mgr.rclone_cmd = ["rclone", "copy", "a:", "b:"]
        with patch.object(mgr, "_is_on_battery", return_value=False):
            with patch.object(mgr, "is_rclone_running", return_value=False):
                with patch.object(mgr, "is_in_schedule_window", return_value=True):
                    with patch.object(mgr, "resume") as mock_resume:
                        mgr._check_battery()
                        mock_resume.assert_called_once()
        assert mgr.state.get("_battery_paused") is False

    def test_no_battery_info_skips(self, tmp_path):
        """When pause_on_battery is False, _check_battery is a no-op."""
        mgr = TransferManager(cm_dir=str(tmp_path))
        mgr.state["pause_on_battery"] = False
        with patch.object(mgr, "_is_on_battery") as mock_battery:
            mgr._check_battery()
            mock_battery.assert_not_called()

    @patch("platform.system", return_value="Linux")
    def test_non_darwin_not_on_battery(self, mock_system, tmp_path):
        """On non-Darwin platforms, _is_on_battery returns False."""
        mgr = TransferManager(cm_dir=str(tmp_path))
        assert mgr._is_on_battery() is False
