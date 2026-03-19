"""PyInstaller runtime hook for CloudHop.

Prepends the bundle directory (sys._MEIPASS) to PATH so that the bundled
rclone binary is found by shutil.which() and subprocess calls without any
code changes to the application.
"""
import os
import sys

if hasattr(sys, '_MEIPASS'):
    bundle_dir = sys._MEIPASS
    os.environ['PATH'] = bundle_dir + os.pathsep + os.environ.get('PATH', '')
