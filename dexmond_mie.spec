# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller build spec for DEXMOND MIE (Windows).
#
# Build:   pyinstaller dexmond_mie.spec
# Output:  dist/DexmondMIE/DexmondMIE.exe  (one-folder build)
#
# The one-folder build is recommended for a security tool: it starts faster and
# is easier for antivirus/SmartScreen to inspect than a single-file build.

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
datas = [
    ('rules', 'rules'),
    ('data/reputation.json', 'data'),
]
datas += collect_data_files('yara')

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
    upx=True,
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
    upx=True,
    upx_exclude=[],
    name='DexmondMIE',
)
