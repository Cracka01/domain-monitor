# PyInstaller spec for domain-monitor
# Produces a single-file Windows executable: dist/domain-monitor.exe
# Build with:  pyinstaller domain-monitor.spec --clean --noconfirm

from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

datas = collect_data_files("domain_monitor", includes=["templates/*.html", "static/*"])

a = Analysis(
    ["pyinstaller_entry.py"],
    pathex=["src"],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "domain_monitor",
        "domain_monitor.app",
        "domain_monitor.cli",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc", "doctest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="domain-monitor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
