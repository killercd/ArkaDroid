from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files

root = Path(SPECPATH).parent
a = Analysis(
    [str(root / 'scripts' / 'droidboard_desktop.py')],
    pathex=[str(root), str(root / 'backend')],
    binaries=[],
    datas=[
        (str(root / 'droidboard' / 'templates'), 'droidboard/templates'),
        (str(root / 'droidboard' / 'static'), 'droidboard/static'),
    ] + collect_data_files('webview'),
    hiddenimports=['sqlalchemy.dialects.sqlite'],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['PyQt5', 'PyQt6', 'PySide2', 'PySide6', 'gtk', 'gi'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True, name='Droidboard',
    debug=False, strip=False, upx=False, console=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='Droidboard')
