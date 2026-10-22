"""Build a portable Windows executable and a GitHub Release ZIP."""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
RELEASE = ROOT / "release"
STAGE = RELEASE / "SoftSweep-win-x64"
APP_NAME = "SoftSweep"
VERSION = "1.1.0"


def run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, check=True, cwd=ROOT)


def ensure_icon() -> Path:
    icon = ROOT / "assets" / "app.ico"
    if not icon.exists():
        if importlib.util.find_spec("PIL") is None:
            raise SystemExit("缺少 Pillow。请先运行: python -m pip install pillow")
        run([sys.executable, "tools/make_icon.py"])
    if not icon.exists():
        raise SystemExit(f"无法生成应用图标：{icon}")
    return icon


def main() -> int:
    if importlib.util.find_spec("PyInstaller") is None:
        raise SystemExit("缺少 PyInstaller。请先运行: python -m pip install pyinstaller")

    icon = ensure_icon()
    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    RELEASE.mkdir(parents=True, exist_ok=True)
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)

    run([
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", APP_NAME,
        "--icon", str(icon),
        "--version-file", str(ROOT / "packaging" / "version_info.txt"),
        "--add-data", f"{ROOT / 'web'};web",
        "--add-data", f"{ROOT / 'core' / 'icon_extract.ps1'};core",
        "--exclude-module", "tkinter",
        "--exclude-module", "unittest",
        "--distpath", str(DIST),
        "--workpath", str(BUILD),
        "--specpath", str(BUILD),
        "app.py",
    ])

    exe = DIST / f"{APP_NAME}.exe"
    if not exe.exists():
        raise SystemExit(f"构建完成但没有找到：{exe}")

    shutil.copy2(exe, STAGE / "SoftSweep.exe")
    shutil.copy2(ROOT / "README.md", STAGE / "README.md")
    shutil.copy2(ROOT / "LICENSE", STAGE / "LICENSE.txt")

    archive = RELEASE / "SoftSweep-win-x64"
    if archive.with_suffix(".zip").exists():
        archive.with_suffix(".zip").unlink()
    shutil.make_archive(str(archive), "zip", root_dir=RELEASE, base_dir=STAGE.name)

    print(f"应用：{exe}")
    print(f"压缩包：{archive.with_suffix('.zip')}")
    print(f"版本：{VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
