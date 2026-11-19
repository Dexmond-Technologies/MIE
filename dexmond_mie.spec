# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller build spec for DEXMOND MIE (Windows).
#
# Build:   pyinstaller dexmond_mie.spec
# Output:  dist/DexmondMIE/DexmondMIE.exe  (one-folder build)
#
# The one-folder build is recommended for a security tool: it starts faster and
# is easier for antivirus/SmartScreen to inspect than a single-file build.

import glob
import importlib.util
import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# uvicorn and watchdog load parts of themselves dynamically, so PyInstaller
# cannot see those imports statically -- collect them explicitly.
hiddenimports = (
    collect_submodules('uvicorn')
    + collect_submodules('watchdog')
    + ['yara', 'pefile', 'colorama', 'multipart',
       'webview', 'pystray', 'PIL', 'requests']
)

# Bundle the YARA rules and the seed reputation list next to the app. These are
# extracted to the temporary resource dir and found via dexmond_mie/paths.py.
# Only the reviewed live rule files (rules/*.yar). Never rules/proposed/ or
# rules/auto_generated.yar (F1: proposals are not loaded until approved).
datas = [(f, 'rules') for f in sorted(glob.glob(os.path.join('rules', '*.yar')))
         if os.path.basename(f) != 'auto_generated.yar']
datas += [
    ('data/reputation.json', 'data'),
    ('config/trusted_publishers.json', 'config'),
]
datas += collect_data_files('yara')
# X12 v2 pinned Authenticode root store, once SENTINEL has provisioned it
if os.path.isfile(os.path.join('trust', 'authenticode_roots.pem')):
    datas.append(('trust/authenticode_roots.pem', 'trust'))
# X12 publisher check on Windows needs signify (requirements-signify.lock);
# without it a valid signature is never treated as an allowlisted publisher.
if importlib.util.find_spec('signify') is not None:
    hiddenimports += collect_submodules('signify')
    for pkg in ('mscerts', 'certvalidator', 'oscrypto', 'asn1crypto'):
        if importlib.util.find_spec(pkg) is not None:
            hiddenimports += collect_submodules(pkg)
            datas += collect_data_files(pkg)

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='DexmondMIE',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # No UPX: MIE's own Packer_UPX rule and packer heuristics flag UPX-packed
    # files, so a packed MIE would flag itself (release audit 2026-11-18).
    upx=False,
    console=False,          # windowed app; set True to see logs while debugging
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/dexmond.ico',   # add your .ico here before shipping
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='DexmondMIE',
)
