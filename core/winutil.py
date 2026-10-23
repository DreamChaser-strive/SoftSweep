"""Windows helpers: safety rules, registry backup, sizing and recycle-bin deletes."""
from __future__ import annotations

import ctypes
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from ctypes import wintypes
from pathlib import Path

IS_FROZEN = bool(getattr(sys, "frozen", False))
APP_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))

if IS_FROZEN:
    _LOCAL_APPDATA_ROOT = Path(
        os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
    )
    DATA_DIR = _LOCAL_APPDATA_ROOT / "SoftSweep"
else:
    DATA_DIR = APP_DIR / "data"

LOG_DIR = DATA_DIR / "logs"
BACKUP_DIR = DATA_DIR / "backups"
for _d in (DATA_DIR, LOG_DIR, BACKUP_DIR):
    _d.mkdir(parents=True, exist_ok=True)

CREATE_NO_WINDOW = 0x08000000
GENERIC_NAMES = {
    "app", "application", "client", "desktop", "common", "shared", "program",
    "programs", "service", "services", "driver", "drivers", "runtime", "update",
    "updater", "installer", "setup", "launcher", "helper", "tools", "tool",
    "microsoft", "windows", "google", "adobe", "tencent", "alibaba", "baidu",
    "netease", "bytedance", "huawei", "xiaomi", "360", "kingsoft", "sogou",
    "office", "browser", "security", "system", "temp", "cache", "data", "config",
    "local", "roaming", "packages", "users", "user", "public", "documents", "desktop_",
}
SHORTCUT_ROOTS: list[Path] = []


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _norm(path: str | os.PathLike) -> str:
    s = os.path.normcase(os.path.abspath(os.path.expandvars(os.fspath(path)))).rstrip("\\/")
    if re.fullmatch(r"[a-z]:", s):
        return s + "\\"
    return s or os.sep


def _same(a: str | os.PathLike, b: str | os.PathLike) -> bool:
    return _norm(a) == _norm(b)


def _within(child: str | os.PathLike, parent: str | os.PathLike) -> bool:
    try:
        c = _norm(child)
        p = _norm(parent)
        return os.path.commonpath([c, p]) == p
    except (ValueError, OSError):
        return False


def _env_path(name: str, default: str) -> str:
    return os.environ.get(name) or default


WINDOWS_DIR = Path(_env_path("SystemRoot", r"C:\Windows"))
SYSTEM_DRIVE = Path(os.environ.get("SystemDrive", "C:") + "\\")
PROGRAM_FILES = Path(_env_path("ProgramFiles", r"C:\Program Files"))
PROGRAM_FILES_X86 = Path(_env_path("ProgramFiles(x86)", r"C:\Program Files (x86)"))
PROGRAM_DATA = Path(_env_path("ProgramData", r"C:\ProgramData"))
USER_PROFILE = Path(_env_path("USERPROFILE", str(Path.home())))
LOCAL_APPDATA = Path(_env_path("LOCALAPPDATA", str(USER_PROFILE / "AppData" / "Local")))
ROAMING_APPDATA = Path(_env_path("APPDATA", str(USER_PROFILE / "AppData" / "Roaming")))
LOCAL_APPDATA_LOW = USER_PROFILE / "AppData" / "LocalLow"
COMMON_START_MENU = PROGRAM_DATA / "Microsoft" / "Windows" / "Start Menu" / "Programs"
USER_START_MENU = ROAMING_APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs"
USER_DESKTOP = USER_PROFILE / "Desktop"
PUBLIC_DESKTOP = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop"
SHORTCUT_ROOTS = [COMMON_START_MENU, USER_START_MENU, USER_DESKTOP, PUBLIC_DESKTOP]

BLOCKED_TREES = {
    WINDOWS_DIR,
    PROGRAM_FILES / "WindowsApps",    PROGRAM_FILES / "Common Files",
    PROGRAM_FILES / "ModifiableWindowsApps",
    PROGRAM_FILES_X86 / "WindowsApps",
    PROGRAM_FILES_X86 / "Common Files",
    PROGRAM_DATA / "Microsoft",
    PROGRAM_DATA / "Package Cache",
    LOCAL_APPDATA / "Package Cache",
    LOCAL_APPDATA / "Microsoft",
    LOCAL_APPDATA / "Temp",
    ROAMING_APPDATA / "Microsoft",
    LOCAL_APPDATA_LOW,
    USER_PROFILE / "Documents",
    USER_PROFILE / "Downloads",
    USER_PROFILE / "Pictures",
    USER_PROFILE / "Videos",
    USER_PROFILE / "Music",
    USER_PROFILE / "Saved Games",
    USER_PROFILE / "OneDrive",
    APP_DIR,
    DATA_DIR,
    SYSTEM_DRIVE / "$Recycle.Bin",
    SYSTEM_DRIVE / "System Volume Information",
}
# Never let a cleanup remove the interpreter this tool is currently running on.
if sys.executable:
    BLOCKED_TREES.add(Path(sys.executable).resolve().parent)

PROTECTED_ROOTS = {
    Path("C:\\"), Path("D:\\"), Path("E:\\"), Path("F:\\"),
    SYSTEM_DRIVE,
    WINDOWS_DIR,
    WINDOWS_DIR / "System32",
    WINDOWS_DIR / "SysWOW64",
    WINDOWS_DIR / "WinSxS",
    PROGRAM_FILES,
    PROGRAM_FILES_X86,
    PROGRAM_DATA,
    PROGRAM_DATA / "Microsoft" / "Windows" / "Start Menu",
    USER_PROFILE,
    USER_PROFILE / "AppData",
    LOCAL_APPDATA,
    ROAMING_APPDATA,
    LOCAL_APPDATA / "Programs",
    LOCAL_APPDATA / "Packages",
    LOCAL_APPDATA / "Temp",
    ROAMING_APPDATA / "Microsoft",
    USER_START_MENU,
    COMMON_START_MENU,
    USER_DESKTOP,
    PUBLIC_DESKTOP,
    *BLOCKED_TREES,
}

REG_VIRTUAL_ROOTS = {
    "HKCU\\SOFTWARE",
    "HKLM\\SOFTWARE",
    "HKLM\\SOFTWARE\\WOW6432NODE",
    "HKCU\\SOFTWARE\\MICROSOFT",
    "HKLM\\SOFTWARE\\MICROSOFT",
}
_UNINSTALL_ROOT_RE = re.compile(
    r"^(HKCU|HKLM)\\SOFTWARE\\(?:WOW6432NODE\\)?MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL\\[^\\]+$",
    re.IGNORECASE,
)
_RUN_KEY_RE = re.compile(
    r"^(HKCU|HKLM)\\SOFTWARE\\(?:WOW6432NODE\\)?(?:MICROSOFT\\WINDOWS\\CURRENTVERSION\\)?(?:RUN|RUNONCE)$",
    re.IGNORECASE,
)


def drive_type_ok(path: str | os.PathLike) -> bool:
    """Only local/disconnected-capable drive letters; never UNC shares."""
    p = os.path.abspath(os.fspath(path))
    drive, rest = os.path.splitdrive(p)
    if not drive or drive.startswith("\\\\") or not rest:
        return False
    try:
        dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive + "\\"))
        # 2 removable, 3 fixed, 5 cdrom, 6 ramdisk. Never accept 4 (network share).
        return dtype in (2, 3, 5, 6)
    except Exception:
        return False


def _is_reparse_point(path: str | os.PathLike) -> bool:
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(ctypes.c_wchar_p(os.fspath(path)))
        if attrs == 0xFFFFFFFF:
            return False
        return bool(attrs & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except Exception:
        return False


def is_safe_dir_path(path: str | os.PathLike, *, trusted: bool = False) -> bool:
    """Defense in depth before recycling a directory.

    The server only exposes audited candidates, but re-check every path right
    before touching disk. Never allow Windows, Program Files root, user profile
    roots, AppData roots, the tool itself, or a parent of any of those.
    """
    try:
        p = os.path.abspath(os.fspath(path))
    except (TypeError, ValueError):
        return False
    if not p or not os.path.exists(p) or not os.path.isdir(p):
        return False
    if not drive_type_ok(p):
        return False
    if _same(p, SYSTEM_DRIVE) or len(Path(p).parts) < 2:
        return False
    if any(part.lower() in {"$recycle.bin", "system volume information"} for part in Path(p).parts):
        return False
    if _is_reparse_point(p):
        return False
    n = _norm(p)
    for prot in PROTECTED_ROOTS:
        if _same(n, prot):
            return False
        # Reject a candidate that contains a protected root (e.g. C:\Users).
        if _within(prot, n) and not _same(prot, n):
            return False
        # Blocked trees are entirely off-limits, but the item root itself
        # must not be one of their parents.
        if _within(n, prot) and prot in BLOCKED_TREES:
            return False
    if _within(APP_DIR, n) or _within(n, APP_DIR) or _within(DATA_DIR, n):
        return False
    if not trusted and len(Path(p).parts) <= 2:
        return False
    # Resolve junctions/symlinks for an extra check. A normal path may live
    # under a redirected system folder; reject if it actually points into a
    # protected area.
    try:
        real = _norm(os.path.realpath(p))
        for prot in PROTECTED_ROOTS:
            if prot in BLOCKED_TREES and _within(real, prot):
                return False
            if _same(real, prot):
                return False
    except OSError:
        return False
    return True


def is_safe_shortcut_path(path: str | os.PathLike) -> bool:
    try:
        p = os.path.abspath(os.fspath(path))
    except (TypeError, ValueError):
        return False
    if not os.path.isfile(p):
        return False
    if Path(p).suffix.lower() not in {".lnk", ".url"}:
        return False
    if not drive_type_ok(p) or _is_reparse_point(p):
        return False
    if not any(_within(p, root) for root in SHORTCUT_ROOTS):
        return False
    return not (_within(APP_DIR, p) or _within(p, APP_DIR))


def is_safe_registry_key(path: str) -> bool:
    if not path or "\\" not in path:
        return False
    upper = path.upper().strip("\\")
    if upper in REG_VIRTUAL_ROOTS:
        return False
    if _UNINSTALL_ROOT_RE.match(upper):
        return True
    if not (upper.startswith("HKCU\\SOFTWARE\\") or upper.startswith("HKLM\\SOFTWARE\\")):
        return False
    parts = upper.split("\\")
    # HKCU\SOFTWARE\VENDOR\PRODUCT at minimum
    if len(parts) < 4:
        return False
    deny_prefixes = [
        "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS",
        "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS",
        "HKCU\\SOFTWARE\\MICROSOFT\\WINDOWSNT",
        "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWSNT",
        "HKCU\\SOFTWARE\\POLICIES",
        "HKLM\\SOFTWARE\\POLICIES",
        "HKCU\\SOFTWARE\\CLASSES",
        "HKLM\\SOFTWARE\\CLASSES",
        "HKCU\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS",
        "HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS",
        "HKLM\\SOFTWARE\\WOW6432NODE\\POLICIES",
        "HKCU\\SOFTWARE\\WOW6432NODE\\POLICIES",
        "HKLM\\SYSTEM",
    ]
    for deny in deny_prefixes:
        if upper == deny or upper.startswith(deny + "\\"):
            return False
    if any(marker in upper for marker in ("\\RUN", "\\RUNONCE")):
        return False
    if parts[-1] in {"SOFTWARE", "MICROSOFT", "WOW6432NODE", "CLIENTS", "CLASSES"}:
        return False
    return True


def is_safe_run_value(key_path: str, value_name: str) -> bool:
    if not _RUN_KEY_RE.match(key_path.upper().strip("\\")):
        return False
    if not value_name or len(value_name) > 512:
        return False
    if value_name in {"(Default)", "Path", "TEMPath"}:
        return False
    return True


# ---------------------------------------------------------------- text helpers

def norm_text(value: str) -> str:
    s = unicodedata.normalize("NFKC", value or "").casefold()
    s = re.sub(r"[™®©]", " ", s)
    s = re.sub(r"\((?:x86|x64|32[- ]?bit|64[- ]?bit)\)", " ", s)
    s = re.sub(r"\b(?:x86|x64|32[- ]?bit|64[- ]?bit)\b", " ", s)
    s = re.sub(r"\bv?\d+(?:\.\d+){1,4}\b", " ", s)
    s = re.sub(r"\b(?:version|版本)\b", " ", s)
    s = re.sub(r"[^0-9a-z\u3400-\u9fff]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def compact(value: str) -> str:
    return norm_text(value).replace(" ", "")


def _has_cjk(s: str) -> bool:
    return bool(re.search(r"[\u3400-\u9fff]", s))


def app_aliases(name: str, publisher: str = "") -> set[str]:
    aliases: set[str] = set()
    pieces = [name or ""]
    # Keep Latin/Chinese names hidden in parentheses or after a slash.
    for part in re.findall(r"\(([^)]+)\)", name or ""):
        pieces.append(part)
    for part in re.split(r"[/|｜]", name or ""):
        pieces.append(part)

    def add(raw: str) -> None:
        c = compact(raw)
        if not c or c in GENERIC_NAMES:
            return
        if _has_cjk(c):
            if len(c) >= 2:
                aliases.add(c)
        elif len(c) >= 3:
            aliases.add(c)

    for piece in pieces:
        add(piece)

    pub_words = [w for w in norm_text(publisher).split() if len(w) >= 3 and w not in GENERIC_NAMES]
    base = norm_text(name)
    words = base.split()
    if pub_words:
        stripped = [w for w in words if w not in pub_words]
        if stripped:
            add(" ".join(stripped))
    # Remove generic tail/middle words (Desktop / Client / App / User / ...).
    tail = [w for w in words if w not in GENERIC_NAMES]
    if tail:
        add(" ".join(tail))
    # Parenthetical already handled. Keep a name without trailing version.
    add(re.sub(r"\s+", " ", re.sub(r"\d+(?:\.\d+)+", " ", name or "")))
    return aliases


def match_folder_to_app(folder_name: str, aliases: set[str]) -> int:
    """Return confidence-ish score: 2 exact alias, 1 useful prefix, 0 no match."""
    c = compact(folder_name)
    if not c or c in GENERIC_NAMES:
        return 0
    if c in aliases:
        return 2
    for alias in aliases:
        if len(alias) >= 5 and c.startswith(alias):
            tail = c[len(alias):]
            # Version suffixes are common in data folders (IdeaIC2024.3,
            # Python311, ...). A pure digit tail still names the same product.
            if tail.isdigit():
                return 2
            if tail in {"files", "file", "data", "cache", "app", "application", "client",
                        "desktop", "config", "settings", "userdata", "user", "profile"}:
                return 1
    return 0


def make_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"{prefix}{digest}"


def display_env_path(path: str) -> str:
    p = path
    pairs = [
        (str(USER_PROFILE), "%USERPROFILE%"),
        (str(LOCAL_APPDATA), "%LOCALAPPDATA%"),
        (str(ROAMING_APPDATA), "%APPDATA%"),
        (str(PROGRAM_DATA), "%ProgramData%"),
        (str(PROGRAM_FILES_X86), "%ProgramFiles(x86)%"),
        (str(PROGRAM_FILES), "%ProgramFiles%"),
        (str(WINDOWS_DIR), "%SystemRoot%"),
    ]
    low = p.lower()
    for real, token in pairs:
        if low.startswith(real.lower()):
            return token + p[len(real):]
    return p


def human_size(num: int | float | None) -> str:
    if num is None:
        return ""
    n = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------- measurement

def measure_path(path: str | os.PathLike, max_seconds: float = 8.0, max_entries: int = 200_000) -> dict:
    """Best-effort size. Never follows reparse points; bounded for UI latency."""
    result = {"bytes": 0, "partial": False, "error": None}
    try:
        if not os.path.exists(path):
            result["error"] = "not_found"
            return result
        if os.path.isfile(path):
            result["bytes"] = os.path.getsize(path)
            return result
    except OSError as exc:
        result["error"] = str(exc)
        return result

    deadline = time.monotonic() + max_seconds
    stack = [os.fspath(path)]
    entries = 0
    total = 0
    partial = False
    while stack:
        if time.monotonic() > deadline or entries >= max_entries:
            partial = True
            break
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for ent in it:
                    entries += 1
                    if entries >= max_entries:
                        partial = True
                        break
                    try:
                        if ent.is_symlink():
                            continue
                        if ent.is_dir(follow_symlinks=False):
                            stack.append(ent.path)
                        elif ent.is_file(follow_symlinks=False):
                            total += ent.stat(follow_symlinks=False).st_size
                    except (OSError, PermissionError):
                        partial = True
                if entries >= max_entries:
                    break
        except (OSError, PermissionError) as exc:
            partial = True
            if result["error"] is None:
                result["error"] = str(exc)
    result["bytes"] = total
    result["partial"] = partial
    return result


# ---------------------------------------------------------------- process/powershell

def run_powershell(script: str, timeout: float = 60.0, *, no_window: bool = True) -> subprocess.CompletedProcess:
    prefix = (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        "try {$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8} catch {};"
    )
    creation = CREATE_NO_WINDOW if no_window else 0
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + script],
        capture_output=True,
        timeout=timeout,
        creationflags=creation,
    )


def decode_output(data: bytes | None) -> str:
    if not data:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gb18030", "mbcs"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def get_shortcut_index(max_age: float = 120.0) -> list[dict]:
    """Return [{path, target}] for shortcuts in Start Menu / Desktop (cached)."""
    global _shortcut_cache
    now = time.monotonic()
    if _shortcut_cache and now - _shortcut_cache[0] < max_age:
        return _shortcut_cache[1]
    roots = [str(r) for r in SHORTCUT_ROOTS if Path(r).exists()]
    if not roots:
        _shortcut_cache = (now, [])
        return []
    roots_ps = ",".join(ps_quote(r) for r in roots)
    script = f"""
$sh = New-Object -ComObject WScript.Shell
$out = @()
$roots = @({roots_ps})
foreach ($r in $roots) {{
  Get-ChildItem -LiteralPath $r -Filter *.lnk -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    try {{
      $sc = $sh.CreateShortcut($_.FullName)
      $out += [PSCustomObject]@{{ path = $_.FullName; target = [string]$sc.TargetPath }}
    }} catch {{ }}
  }}
}}
$out | ConvertTo-Json -Compress -Depth 3
"""
    try:
        proc = run_powershell(script, timeout=25)
        text = decode_output(proc.stdout).strip()
        if not text:
            data = []
        else:
            import json
            data = json.loads(text)
            if isinstance(data, dict):
                data = [data]
        cleaned = []
        for item in data:
            if isinstance(item, dict) and item.get("path"):
                cleaned.append({"path": item["path"], "target": item.get("target") or ""})
        _shortcut_cache = (now, cleaned)
        return cleaned
    except Exception:
        _shortcut_cache = (now, [])
        return []


_shortcut_cache: tuple[float, list[dict]] | None = None


def folder_mtime_iso(path: str | os.PathLike) -> str | None:
    try:
        return time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(path)))
    except OSError:
        return None


# ---------------------------------------------------------------- recycle / registry

class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", ctypes.c_ushort),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


def delete_path(path: str | os.PathLike, *, permanent: bool = False) -> dict:
    """Delete a file/folder via Explorer semantics. Returns {ok, error}."""
    p = os.path.abspath(os.fspath(path))
    if not os.path.exists(p):
        return {"ok": True, "missing": True}
    is_dir = os.path.isdir(p)
    if is_dir:
        if not is_safe_dir_path(p, trusted=True):
            return {"ok": False, "error": "安全策略拒绝删除该目录"}
    else:
        if Path(p).suffix.lower() not in {".lnk", ".url"}:
            return {"ok": False, "error": "只允许清理快捷方式文件"}
        if not is_safe_shortcut_path(p):
            return {"ok": False, "error": "安全策略拒绝删除该文件"}

    flags = 0x0010 | 0x0004 | 0x0400 | 0x0200  # no confirm, silent, no error UI
    if not permanent:
        flags |= 0x0040  # ALLOWUNDO
    op = _SHFILEOPSTRUCTW()
    op.wFunc = 3  # FO_DELETE
    op.pFrom = p + "\0\0"
    op.pTo = None
    op.fFlags = flags
    code = 0
    try:
        code = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    except Exception as exc:
        code = -1
        err = str(exc)
    if code == 0 and not os.path.exists(p):
        return {"ok": True, "recycled": not permanent}
    if permanent:
        try:
            if is_dir:
                shutil.rmtree(p)
            else:
                os.remove(p)
            if not os.path.exists(p):
                return {"ok": True, "recycled": False}
        except Exception as exc:
            return {"ok": False, "error": f"{exc} (SHFileOperation={code})"}
    else:
        # Long paths can exceed the legacy shell limit; use .NET recycle API.
        try:
            method = "DeleteDirectory" if is_dir else "DeleteFile"
            script = (
                "Add-Type -AssemblyName Microsoft.VisualBasic; "
                f"[Microsoft.VisualBasic.FileIO.FileSystem]::{method}({ps_quote(p)},"
                "'OnlyErrorDialogs','SendToRecycleBin');"
            )
            proc = run_powershell(script, timeout=45)
            if not os.path.exists(p):
                return {"ok": True, "recycled": True}
            return {"ok": False, "error": (decode_output(proc.stderr).strip() or f"回收站操作失败 (code {code})")}
        except Exception as exc:
            return {"ok": False, "error": f"{exc} (SHFileOperation={code})"}
    return {"ok": False, "error": f"删除失败 (code {code})"}


def reg_export(key_path: str, destination: str | os.PathLike) -> dict:
    try:
        os.makedirs(os.path.dirname(os.fspath(destination)), exist_ok=True)
        proc = subprocess.run(
            ["reg.exe", "export", key_path, os.fspath(destination), "/y"],
            capture_output=True,
            timeout=45,
            creationflags=CREATE_NO_WINDOW,
        )
        ok = proc.returncode == 0 and os.path.exists(destination) and os.path.getsize(destination) > 0
        return {"ok": ok, "error": None if ok else (decode_output(proc.stderr).strip() or "注册表导出失败")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _reg_split(path: str) -> tuple[int, str]:
    upper = path.upper().strip("\\")
    if upper.startswith("HKCU\\"):
        return _HKEY_CURRENT_USER, path[len("HKCU\\"):]
    if upper.startswith("HKLM\\"):
        return _HKEY_LOCAL_MACHINE, path[len("HKLM\\"):]
    raise ValueError("不支持的注册表根键")


_HKEY_CURRENT_USER = 0x80000001
_HKEY_LOCAL_MACHINE = 0x80000002


def _delete_reg_tree(hkey: int, subkey: str) -> None:
    import winreg

    try:
        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            children = []
            idx = 0
            while True:
                try:
                    children.append(winreg.EnumKey(key, idx))
                    idx += 1
                except OSError:
                    break
        for child in children:
            _delete_reg_tree(hkey, subkey + "\\" + child)
        winreg.DeleteKey(hkey, subkey)
    except FileNotFoundError:
        return


def delete_registry_key(key_path: str, backup_dest: str) -> dict:
    if not is_safe_registry_key(key_path):
        return {"ok": False, "error": "安全策略拒绝删除该注册表项"}
    backup = reg_export(key_path, backup_dest)
    if not backup["ok"]:
        return {"ok": False, "error": "注册表备份失败，已中止删除: " + str(backup.get("error"))}
    try:
        hkey, subkey = _reg_split(key_path)
        _delete_reg_tree(hkey, subkey)
        return {"ok": True, "backup": backup_dest}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "backup": backup_dest}


def delete_registry_value(key_path: str, value_name: str, backup_dest: str) -> dict:
    if not is_safe_run_value(key_path, value_name):
        return {"ok": False, "error": "安全策略拒绝删除该启动项"}
    backup = reg_export(key_path, backup_dest)
    if not backup["ok"]:
        return {"ok": False, "error": "注册表备份失败，已中止删除: " + str(backup.get("error"))}
    import winreg

    try:
        hkey, subkey = _reg_split(key_path)
        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)
        return {"ok": True, "backup": backup_dest}
    except FileNotFoundError:
        return {"ok": True, "missing": True, "backup": backup_dest}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "backup": backup_dest}


def open_local_path(path: str | os.PathLike) -> None:
    p = os.path.abspath(os.fspath(path))
    if not os.path.exists(p):
        raise FileNotFoundError(p)
    os.startfile(p)


def runas_elevate(exe: str, params: str, cwd: str | None = None) -> int:
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, cwd, 1
        )
        return int(result)
    except Exception:
        return 0


def command_executable(command: str) -> str | None:
    if not command:
        return None
    expanded = os.path.expandvars(command.strip())
    if expanded.startswith('"'):
        end = expanded.find('"', 1)
        if end > 0:
            return expanded[1:end]
    m = re.match(r"(.+?\.exe)\b", expanded, re.IGNORECASE)
    if m:
        return m.group(1).strip().strip('"')
    return expanded.split(" ")[0].strip('"')


def parse_uninstall_command(command: str) -> str:
    return os.path.expandvars((command or "").strip())


def system_drive_is(path: str | os.PathLike) -> bool:
    try:
        return os.path.splitdrive(os.path.abspath(os.fspath(path)))[0].upper() == os.path.splitdrive(str(SYSTEM_DRIVE))[0].upper()
    except Exception:
        return False
