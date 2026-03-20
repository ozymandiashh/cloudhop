"""Cross-platform desktop notifications for CloudHop."""

import platform
import subprocess


def notify(title: str, message: str) -> None:
    """Send a desktop notification. Fails silently on all errors."""
    try:
        system = platform.system()
        if system == "Darwin":
            # Escape backslashes and quotes for AppleScript string literals
            safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
            safe_message = message.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display notification "{safe_message}" with title "{safe_title}"',
                ],
                capture_output=True,
                timeout=5,
            )
        elif system == "Linux":
            subprocess.run(
                ["notify-send", title, message],
                capture_output=True,
                timeout=5,
            )
        # Windows: requires pywin32 or plyer - skip for v0.7.0
    except Exception:
        pass
