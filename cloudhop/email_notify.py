"""CloudHop email notifications via SMTP."""

import logging
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("cloudhop.email_notify")


def send_email(subject: str, body_html: str, settings: dict) -> bool:
    """Send an HTML email via SMTP. Returns True on success, False on failure."""
    host = str(settings.get("email_smtp_host", "")).strip()
    port = int(settings.get("email_smtp_port", 587))
    use_tls = settings.get("email_smtp_tls", True)
    email_from = str(settings.get("email_from", "")).strip()
    email_to = str(settings.get("email_to", "")).strip()
    username = str(settings.get("email_username", "")).strip()
    password = str(settings.get("email_password", ""))

    if not host or not email_from or not email_to:
        logger.warning("Email not sent: missing host, from, or to address")
        return False

    msg = MIMEText(body_html, "html")
    msg["Subject"] = subject
    msg["From"] = email_from
    msg["To"] = email_to

    try:
        if port == 465:
            smtp = smtplib.SMTP_SSL(host, port, timeout=30)
        else:
            smtp = smtplib.SMTP(host, port, timeout=30)
            if use_tls:
                smtp.starttls()

        if username:
            smtp.login(username, password)

        smtp.sendmail(email_from, [email_to], msg.as_string())
        smtp.quit()
        logger.info("Email sent to %s (subject: %s)", email_to, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s", email_to)
        return False


def build_completion_email(status: dict, version: str) -> tuple:
    """Build subject and HTML body for a transfer completion/failure email."""
    files_done = status.get("global_files_done", 0)
    transferred = status.get("global_transferred", "")
    pct = status.get("global_pct", 0)
    elapsed = status.get("global_elapsed", "")
    errors = status.get("errors", 0)
    error_messages = status.get("error_messages", [])

    if pct >= 99:
        subject = "CloudHop: Transfer Complete"
        header_color = "#22c55e"
        header_text = "Transfer Complete"
    else:
        subject = "CloudHop: Transfer Failed"
        header_color = "#ef4444"
        header_text = "Transfer Failed"

    error_section = ""
    if errors > 0 and error_messages:
        items = "".join(f"<li style='margin-bottom:4px;'>{msg}</li>" for msg in error_messages[:5])
        error_section = (
            "<div style='margin-top:16px;'>"
            "<strong style='color:#ef4444;'>Errors:</strong>"
            f"<ul style='margin:8px 0;padding-left:20px;'>{items}</ul>"
            "</div>"
        )

    body_html = (
        "<div style='background:#f5f5f5;padding:32px;font-family:-apple-system,sans-serif;'>"
        "<div style='background:#fff;max-width:500px;margin:0 auto;border-radius:8px;"
        "overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);'>"
        f"<div style='background:{header_color};padding:20px 24px;'>"
        f"<h2 style='margin:0;color:#fff;font-size:20px;'>{header_text}</h2>"
        "</div>"
        "<div style='padding:24px;'>"
        "<table style='width:100%;border-collapse:collapse;'>"
        "<tr><td style='padding:8px 0;color:#666;'>Files transferred</td>"
        f"<td style='padding:8px 0;text-align:right;font-weight:600;'>{files_done}</td></tr>"
        "<tr><td style='padding:8px 0;color:#666;'>Total size</td>"
        f"<td style='padding:8px 0;text-align:right;font-weight:600;'>{transferred}</td></tr>"
        "<tr><td style='padding:8px 0;color:#666;'>Duration</td>"
        f"<td style='padding:8px 0;text-align:right;font-weight:600;'>{elapsed}</td></tr>"
        "</table>"
        f"{error_section}"
        f"<p style='color:#888;font-size:13px;margin-top:24px;border-top:1px solid #eee;"
        f"padding-top:16px;'>Sent by CloudHop v{version}</p>"
        "</div></div></div>"
    )

    return (subject, body_html)
