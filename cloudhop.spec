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

# Resolve the rclone binary - search any architecture, then fall back to PATH
rclone_bins = glob.glob('/tmp/rclone-*/rclone') + glob.glob('/tmp/rclone-*/rclone.exe') + ['rclone']
RCLONE_BIN = next((r for r in rclone_bins if os.path.exists(r)), 'rclone')

a = Analysis(
    ['cloudhop_main.py'],
    pathex=[],
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
    console=False,
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

app = BUNDLE(
    coll,
    name='CloudHop.app',
    icon='CloudHop.icns',
    bundle_identifier='io.github.husamsoboh-cyber.cloudhop',
    info_plist={
        'CFBundleName': 'CloudHop',
        'CFBundleDisplayName': 'CloudHop',
        'CFBundleVersion': '0.9.0',
        'CFBundleShortVersionString': '0.9.0',
        'CFBundleInfoDictionaryVersion': '6.0',
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '10.15',
    },
)
