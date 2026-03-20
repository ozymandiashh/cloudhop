"""Tests for cloudhop.cli subcommands."""

import json
from unittest.mock import MagicMock, patch

from cloudhop.cli import _cli_subcommand


def _mock_api_response(data, cookies=""):
    """Create a mock urlopen response."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.headers = MagicMock()
    mock_resp.headers.get.return_value = cookies
    return mock_resp


class TestCliStatus:
    @patch("urllib.request.urlopen")
    def test_status_returns_info(self, mock_urlopen, capsys):
        """cloudhop status prints transfer info."""
        mock_urlopen.return_value = _mock_api_response(
            {
                "global_pct": 75.0,
                "global_transferred": "150 GiB",
                "global_total": "200 GiB",
                "speed": "10 MiB/s",
                "eta": "30m",
                "rclone_running": True,
                "errors": 0,
                "global_files_done": 5000,
                "global_files_total": 8000,
            }
        )
        result = _cli_subcommand("status")
        assert result is True
        output = capsys.readouterr().out
        assert "75.0%" in output
        assert "Transferring" in output

    @patch("urllib.request.urlopen", side_effect=Exception("refused"))
    def test_status_server_not_running(self, mock_urlopen, capsys):
        """cloudhop status shows message when server is down."""
        result = _cli_subcommand("status")
        assert result is True
        output = capsys.readouterr().out
        assert "not running" in output

    def test_unknown_command(self):
        """Unknown subcommand returns False."""
        assert _cli_subcommand("unknown") is False


class TestCliPauseResume:
    @patch("urllib.request.urlopen")
    def test_pause_success(self, mock_urlopen, capsys):
        """cloudhop pause prints success message."""
        mock_urlopen.return_value = _mock_api_response(
            {"ok": True, "msg": "Stopped rclone (PID 1234)"},
            cookies="csrf_token=abc123; Path=/",
        )
        result = _cli_subcommand("pause")
        assert result is True
        output = capsys.readouterr().out
        assert "1234" in output

    @patch("urllib.request.urlopen")
    def test_resume_success(self, mock_urlopen, capsys):
        """cloudhop resume prints success message."""
        mock_urlopen.return_value = _mock_api_response(
            {"ok": True, "msg": "Started rclone (PID 5678)"},
            cookies="csrf_token=abc123; Path=/",
        )
        result = _cli_subcommand("resume")
        assert result is True
        output = capsys.readouterr().out
        assert "5678" in output


class TestCliHistory:
    @patch("urllib.request.urlopen")
    def test_history_shows_entries(self, mock_urlopen, capsys):
        """cloudhop history lists transfers."""
        mock_urlopen.return_value = _mock_api_response(
            [
                {"label": "OneDrive -> Google Drive", "sessions": 5},
                {"label": "Dropbox -> S3", "sessions": 2},
            ]
        )
        result = _cli_subcommand("history")
        assert result is True
        output = capsys.readouterr().out
        assert "OneDrive" in output
        assert "5 sessions" in output

    @patch("urllib.request.urlopen")
    def test_history_empty(self, mock_urlopen, capsys):
        """cloudhop history shows message when empty."""
        mock_urlopen.return_value = _mock_api_response([])
        result = _cli_subcommand("history")
        assert result is True
        output = capsys.readouterr().out
        assert "No transfer history" in output
