# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for CloudHop – Windows one-file build.

Produces a single CloudHop.exe that bundles rclone.exe, HTML templates,
and static assets.

The runtime hook prepends _MEIPASS to PATH so shutil.which("rclone")
and subprocess calls to "rclone" find the bundled binary automatically.
"""

import glob
import os

# Resolve the rclone binary – CI puts rclone.exe in cwd
rclone_bins = (
    glob.glob("rclone.exe")
    + glob.glob("rclone-*/rclone.exe")
    + glob.glob("/tmp/rclone-*/rclone.exe")
    + ["rclone.exe"]
)
RCLONE_BIN = next((r for r in rclone_bins if os.path.exists(r)), "rclone.exe")

a = Analysis(
    ["cloudhop_main.py"],
    pathex=[],
    binaries=[
        (RCLONE_BIN, "."),  # rclone binary -> root of _MEIPASS
    ],
    datas=[
        ("cloudhop/templates/*.html", "cloudhop/templates"),
        ("cloudhop/static", "cloudhop/static"),
    ],
    hiddenimports=[
        "webview",
        "webview.platforms",
        "webview.platforms.edgechromium",
        "webview.util",
        "webview.event",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=["rthook_cloudhop.py"],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="CloudHop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    icon="cloudhop.ico",
)
