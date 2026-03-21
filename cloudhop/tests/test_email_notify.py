"""Tests for cloudhop.email_notify module."""

from unittest.mock import MagicMock, patch

from cloudhop.email_notify import build_completion_email, send_email


def _base_settings(**overrides):
    s = {
        "email_smtp_host": "smtp.example.com",
        "email_smtp_port": 587,
        "email_smtp_tls": True,
        "email_from": "test@example.com",
        "email_to": "user@example.com",
        "email_username": "testuser",
        "email_password": "testpass",
    }
    s.update(overrides)
    return s


class TestSendEmail:
    def test_send_email_success(self):
        with patch("cloudhop.email_notify.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value = mock_smtp

            result = send_email("Test", "<p>Hello</p>", _base_settings())

            assert result is True
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once_with("testuser", "testpass")
            mock_smtp.sendmail.assert_called_once()
            mock_smtp.quit.assert_called_once()

    def test_send_email_ssl_port_465(self):
        with patch("cloudhop.email_notify.smtplib.SMTP_SSL") as mock_ssl_cls:
            mock_smtp = MagicMock()
            mock_ssl_cls.return_value = mock_smtp

            result = send_email("Test", "<p>Hello</p>", _base_settings(email_smtp_port=465))

            assert result is True
            mock_ssl_cls.assert_called_once_with("smtp.example.com", 465, timeout=30)
            mock_smtp.sendmail.assert_called_once()

    def test_send_email_failure_returns_false(self):
        with patch("cloudhop.email_notify.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp_cls.side_effect = Exception("Connection refused")

            result = send_email("Test", "<p>Hello</p>", _base_settings())

            assert result is False

    def test_send_email_timeout(self):
        with patch("cloudhop.email_notify.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp_cls.side_effect = TimeoutError("Timed out")

            result = send_email("Test", "<p>Hello</p>", _base_settings())

            assert result is False

    def test_send_email_no_host_returns_false(self):
        result = send_email("Test", "<p>Hello</p>", _base_settings(email_smtp_host=""))
        assert result is False

    def test_send_email_no_password_still_works(self):
        with patch("cloudhop.email_notify.smtplib.SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value = mock_smtp

            settings = _base_settings(email_username="", email_password="")
            result = send_email("Test", "<p>Hello</p>", settings)

            assert result is True
            mock_smtp.login.assert_not_called()
            mock_smtp.sendmail.assert_called_once()


class TestBuildCompletionEmail:
    def test_build_completion_email_complete(self):
        status = {
            "global_files_done": 42,
            "global_transferred": "1.5 GiB",
            "global_pct": 100,
            "global_elapsed": "5m30s",
            "errors": 0,
            "error_messages": [],
        }
        subject, body = build_completion_email(status, "0.12.0")

        assert "Complete" in subject
        assert "42" in body
        assert "1.5 GiB" in body
        assert "5m30s" in body
        assert "#22c55e" in body

    def test_build_completion_email_failed(self):
        status = {
            "global_files_done": 10,
            "global_transferred": "500 MiB",
            "global_pct": 50,
            "global_elapsed": "2m",
            "errors": 2,
            "error_messages": ["File not found", "Permission denied"],
        }
        subject, body = build_completion_email(status, "0.12.0")

        assert "Failed" in subject
        assert "#ef4444" in body
        assert "File not found" in body
        assert "Permission denied" in body
