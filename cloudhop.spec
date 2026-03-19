# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for CloudHop.

Data layout inside _MEIPASS:
  cloudhop/templates/dashboard.html
  cloudhop/templates/wizard.html
  cloudhop/static/dashboard.css  (+ js, svg)
  rclone                          <- bundled rclone binary

The runtime hook prepends _MEIPASS to PATH so shutil.which("rclone")
and subprocess calls to "rclone" find the bundled binary automatically.
"""

import os, glob

# Resolve the rclone binary (the extracted folder from the zip)
rclone_matches = glob.glob('/tmp/rclone-*-osx-amd64/rclone')
if not rclone_matches:
    raise FileNotFoundError(
        "rclone binary not found at /tmp/rclone-*-osx-amd64/rclone. "
        "Run: cd /tmp && curl -LO https://downloads.rclone.org/rclone-current-osx-amd64.zip && unzip -o rclone-current-osx-amd64.zip"
    )
RCLONE_BIN = rclone_matches[0]

a = Analysis(
    ['cloudhop_main.py'],
    pathex=['/tmp/cloudmirror'],
    binaries=[
        (RCLONE_BIN, '.'),          # rclone binary -> root of _MEIPASS
    ],
    datas=[
        ('cloudhop/templates/*.html', 'cloudhop/templates'),
        ('cloudhop/static',           'cloudhop/static'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['rthook_cloudhop.py'],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CloudHop',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,            # keep True so startup messages are visible
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='cloudhop/static/favicon.svg',  # SVG not supported; skip for now
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CloudHop',
)
