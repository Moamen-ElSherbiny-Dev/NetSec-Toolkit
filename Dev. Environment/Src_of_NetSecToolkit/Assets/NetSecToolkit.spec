# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['GUI.py'],
    pathex=[],
    binaries=[],
    datas=[('PortScannerProgram.py', '.'), ('AppConnectionControlProgram.py', '.'), ('LiveNetworkMonitoringProgram.py', '.'), ('PacketFilteringProgram.py', '.'), ('ServicesDictionary.py', '.'), ('Assets/NetSec_logo.png', 'Assets')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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
    [],
    name='GUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='Assets/File_of_Version_Info.txt',
    icon=['Assets/NetSec_ICON.ico'],
)
