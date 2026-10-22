"""Application icon extraction and on-disk cache.

Icons are extracted once per application in a background batch so the scan
itself stays fast. Win32 icons come from the registered DisplayIcon or an
installed executable; Store apps use their manifest logo assets. The frontend
falls back to a letter tile whenever an icon cannot be produced.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import winutil as wu

ICON_DIR = wu.DATA_DIR / "icon-cache"
ICON_DIR.mkdir(parents=True, exist_ok=True)
_SCRIPT = Path(__file__).resolve().parent / "icon_extract.ps1"
APP_ID_RE = re.compile(r"^[au][0-9a-f]{16}$")
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp"}
ICON_SUFFIXES = {".exe", ".dll", ".ico"}
BATCH_SIZE = 24

_versions: dict[str, str] = {}
_lock = threading.RLock()
_worker: threading.Thread | None = None
_pending: list[dict] | None = None
_msi_cache: dict[str, str] = {}
_MSI_GUID_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
)

_BAD_EXE = re.compile(
    r"(?:^|[-_.\s])(?:unins\d*|uninstall|uninst|setup|install|update|updater|"
    r"upgrade|repair|crash|reporter|feedback|service|helper|elevate|"
    r"maintenance|remove|config|settings|restart)(?:[-_.\s]|$)",
    re.IGNORECASE,
)


def valid_app_id(app_id: str) -> bool:
    return bool(APP_ID_RE.fullmatch(app_id or ""))


def icon_path(app_id: str) -> Path:
    return ICON_DIR / f"{app_id}.png"


def version_for(app_id: str) -> str | None:
    if not valid_app_id(app_id):
        return None
    with _lock:
        return _versions.get(app_id)


def _valid_png(path: Path) -> bool:
    try:
        if path.stat().st_size <= 64:
            return False
        with path.open("rb") as fh:
            return fh.read(8) == b"\x89PNG\r\n\x1a\n"
    except OSError:
        return False


def _remember(app_id: str) -> str | None:
    path = icon_path(app_id)
    if not _valid_png(path):
        return None
    try:
        version = f"{int(path.stat().st_mtime_ns):x}"
    except OSError:
        return None
    with _lock:
        _versions[app_id] = version
    return version


def _load_existing() -> None:
    try:
        entries = list(os.scandir(ICON_DIR))
    except OSError:
        return
    for entry in entries:
        if not entry.is_file() or not entry.name.lower().endswith(".png"):
            continue
        app_id = entry.name[:-4]
        if valid_app_id(app_id):
            _remember(app_id)


def _log(message: str) -> None:
    try:
        with (wu.LOG_DIR / "icons.log").open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except OSError:
        pass


# --------------------------------------------------------------- source hints
def _split_icon_ref(value: str, install_location: str = "") -> tuple[str, int] | None:
    raw = str(value or "").strip().strip("\x00")
    if not raw or raw.startswith("@{") or raw.startswith("@"):
        return None
    raw = os.path.expandvars(raw)
    index = 0
    matched = re.match(r"^(.*?),\s*(-?\d+)\s*$", raw)
    if matched:
        raw = matched.group(1).strip()
        try:
            index = max(0, int(matched.group(2)))
        except ValueError:
            index = 0
    raw = raw.strip().strip('"').strip()
    if not raw:
        return None
    if not os.path.isabs(raw) and install_location:
        raw = os.path.join(install_location, raw)
    raw = os.path.abspath(raw)
    if not os.path.isfile(raw):
        return None
    return raw, index


def _display_icon_sources(app: dict) -> list[dict]:
    result = []
    ref = _split_icon_ref(app.get("display_icon") or "", app.get("install_location") or "")
    if ref:
        path, index = ref
        suffix = Path(path).suffix.lower()
        if suffix in IMAGE_SUFFIXES:
            result.append({"path": path, "type": "image"})
        elif suffix in ICON_SUFFIXES:
            result.append({"path": path, "type": "icon", "index": index})
    return result


def _uninstall_exe_path(app: dict) -> str:
    command = str(app.get("uninstall_string") or "").strip()
    if not command:
        return ""
    if command.casefold().startswith("msiexec"):
        return ""
    quoted = re.match(r'^\s*"([^"]+?\.exe)"', command, re.IGNORECASE)
    bare = re.match(r"^\s*([A-Za-z]:\\[^\"]*?\.exe)(?:\s|,|$)", command, re.IGNORECASE)
    if not bare:
        bare = re.match(r"^\s*(\S+?\.exe)(?:\s|,|$)", command, re.IGNORECASE)
    path = (quoted.group(1) if quoted else bare.group(1) if bare else "").strip()
    if not path:
        return ""
    path = os.path.expandvars(path)
    if not os.path.isabs(path):
        location = app.get("install_location") or ""
        if location:
            path = os.path.join(location, path)
    try:
        path = os.path.abspath(path)
    except OSError:
        return ""
    return path if os.path.isfile(path) else ""


def _uninstall_icon_source(app: dict) -> list[dict]:
    path = _uninstall_exe_path(app)
    if not path:
        return []
    return [{"path": path, "type": "icon", "index": 0}]


def _msi_product_icon_source(app: dict) -> list[dict]:
    """Use the icon registered with Windows Installer for MSI products.

    Some MSI packages only register themselves through MsiExec and expose the
    product artwork through ARPPRODUCTICON rather than a DisplayIcon value.
    """
    command = str(app.get("uninstall_string") or "")
    if "msiexec" not in command.casefold():
        return []
    match = _MSI_GUID_RE.search(command)
    if not match:
        return []
    code = match.group(0).upper()
    with _lock:
        if code in _msi_cache:
            cached = _msi_cache[code]
        else:
            cached = None
    if cached is None:
        cached = ""
        try:
            import ctypes

            msi = ctypes.WinDLL("msi")
            buffer = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(len(buffer))
            result = msi.MsiGetProductInfoW(
                ctypes.c_wchar_p(code),
                ctypes.c_wchar_p("ProductIcon"),
                buffer,
                ctypes.byref(size),
            )
            if result == 0:
                cached = buffer.value.strip().strip('"')
        except Exception:
            cached = ""
        with _lock:
            _msi_cache[code] = cached
    if not cached:
        return []
    try:
        if not os.path.isfile(cached):
            return []
    except OSError:
        return []
    suffix = Path(cached).suffix.lower()
    if suffix in IMAGE_SUFFIXES:
        return [{"path": cached, "type": "image"}]
    return [{"path": cached, "type": "icon", "index": 0}]


def _scan_exe_dir(directory: Path, app: dict, aliases: set[str]) -> list[tuple[float, str]]:
    found: list[tuple[float, str]] = []
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return found
    for entry in entries:
        try:
            if not entry.is_file() or not entry.name.lower().endswith(".exe"):
                continue
            path = entry.path
            stem = wu.compact(Path(entry.name).stem)
            if not stem:
                continue
            low = Path(entry.name).stem.casefold()
            score = 0.0
            if stem in aliases:
                score += 120
            else:
                for alias in aliases:
                    if len(alias) >= 2 and alias in stem:
                        score += 60
                    elif len(stem) >= 3 and stem in alias:
                        score += 30
            if path.lower() == (app.get("display_icon") or "").lower():
                score += 10
            if _BAD_EXE.search(low):
                score -= 260
            if low in {"msiexec", "rundll32", "regsvr32"}:
                score -= 500
            if directory.name.lower() in {"bin", "x64", "x86"}:
                score -= 4
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            if size > 1024 * 1024:
                score += 6
            elif size < 16 * 1024:
                score -= 20
            if score > -200:
                found.append((score, path))
        except OSError:
            continue
    return found


def _install_exe_sources(app: dict) -> list[dict]:
    location = app.get("install_location") or ""
    uninstall_path = _uninstall_exe_path(app)
    roots: list[Path] = []
    seen_roots: set[str] = set()

    def add_root(candidate: Path) -> None:
        try:
            if not candidate.is_dir():
                return
            key = os.path.normcase(str(candidate))
            if key in seen_roots:
                return
            seen_roots.add(key)
            roots.append(candidate)
        except OSError:
            return

    base: Path | None = None
    if location and os.path.isdir(location):
        try:
            base = Path(location)
            add_root(base)
            for child in ("bin", "app", "x64", "x86"):
                add_root(base / child)
        except (OSError, ValueError):
            base = None
    if uninstall_path:
        parent = Path(uninstall_path).parent
        if len(parent.parts) >= 3:
            add_root(parent)
            for child in ("bin", "app", "x64", "x86"):
                add_root(parent / child)

    aliases = {wu.compact(alias) for alias in (app.get("aliases") or []) if alias}
    aliases.add(wu.compact(app.get("name") or ""))
    aliases.discard("")

    found: list[tuple[float, str]] = []
    for root in roots:
        found.extend(_scan_exe_dir(root, app, aliases))

    # Some packages register a product-level folder (for example a JDK root)
    # with the real executables one level below. Inspect only a small number
    # of immediate child folders to keep icon extraction bounded.
    if not found and base is not None:
        children: list[Path] = []
        try:
            for entry in os.scandir(base):
                try:
                    if entry.is_dir(follow_symlinks=False):
                        children.append(Path(entry.path))
                except OSError:
                    continue
        except OSError:
            children = []
        for child in children[:6]:
            for candidate in (child, child / "bin", child / "app"):
                if candidate.is_dir():
                    found.extend(_scan_exe_dir(candidate, app, aliases))

    found.sort(key=lambda item: (-item[0], len(item[1]), item[1].casefold()))

    result = []
    seen = set()
    for _score, path in found[:4]:
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        result.append({"path": path, "type": "icon", "index": 0})
    return result


def _version_parts(text: str) -> list[tuple[int, ...]]:
    result = []
    for match in re.finditer(r"(?<!\d)(\d+(?:\.\d+){1,3})(?!\d)", text or ""):
        try:
            result.append(tuple(int(bit) for bit in match.group(1).split(".")))
        except ValueError:
            continue
    return result


def _versions_compatible(app_versions: list[tuple[int, ...]],
                         shortcut_versions: list[tuple[int, ...]]) -> bool:
    if not app_versions or not shortcut_versions:
        return True
    for app_version in app_versions:
        for shortcut_version in shortcut_versions:
            width = min(len(app_version), len(shortcut_version), 3)
            if width >= 2 and app_version[:width] == shortcut_version[:width]:
                return True
    return False


def _shortcut_sources(app: dict, shortcuts: list[dict]) -> list[dict]:
    aliases = {wu.compact(alias) for alias in (app.get("aliases") or []) if alias}
    aliases.add(wu.compact(app.get("name") or ""))
    aliases.discard("")
    publisher = wu.compact(app.get("publisher") or "")
    name_versions = _version_parts(str(app.get("name") or ""))
    rejected = {"cmd", "msiexec", "rundll32", "hh", "uninst", "uninstall", "unins000"}
    matches: list[tuple[float, str]] = []
    for shortcut in shortcuts:
        target = str(shortcut.get("target") or "")
        if not target or not target.lower().endswith(".exe"):
            continue
        try:
            if not os.path.isfile(target):
                continue
        except OSError:
            continue
        path = str(shortcut.get("path") or "")
        target_name = Path(target)
        if target_name.stem.casefold() in rejected:
            continue
        if "uninstall" in path.casefold() and "uninst" in target_name.stem.casefold():
            continue
        if not _versions_compatible(name_versions, _version_parts(path)):
            continue
        path_stem = Path(path).stem if path else target_name.stem
        hay_name = wu.compact(path_stem)
        hay_target = wu.compact(target_name.stem)
        hay_path = wu.compact(os.path.splitext(path)[0])
        hay_full = hay_name + hay_path + hay_target
        score = 0.0
        for alias in aliases:
            if alias == hay_name or alias == hay_target:
                score = max(score, 120.0)
            elif alias in hay_name or alias in hay_target:
                score = max(score, 85.0)
            elif len(alias) >= 4 and alias in hay_path:
                score = max(score, 65.0)
            elif len(alias) >= 4 and alias[:6] in hay_full:
                score = max(score, 35.0)
        if publisher and len(publisher) >= 5 and publisher in hay_path:
            score += 25
        if name_versions and _versions_compatible(name_versions, _version_parts(path)):
            score += 30
        if score >= 80:
            matches.append((score, target))
    matches.sort(key=lambda item: (-item[0], len(item[1]), item[1].casefold()))
    result = []
    seen = set()
    for _score, target in matches:
        key = os.path.normcase(target)
        if key in seen:
            continue
        seen.add(key)
        result.append({"path": target, "type": "icon", "index": 0})
        if len(result) >= 3:
            break
    return result


def _asset_variant_score(name: str, stem: str) -> float:
    low = name.casefold()
    target = re.search(r"targetsize-(\d+)", low)
    scale = re.search(r"scale-(\d+)", low)
    if target:
        size = int(target.group(1))
    elif scale:
        base = 150.0 if "square150" in stem.casefold() else 44.0 if "square44" in stem.casefold() else 50.0
        size = float(scale.group(1)) * base / 100.0
    else:
        size = 44.0
    score = min(size, 256.0)
    if "altform-unplated" in low:
        score += 6
    if "altform-lightunplated" in low:
        score -= 3
    if "contrast" in low:
        score -= 500
    return score


def _uwp_logo_candidates(install_location: str, reference: str) -> list[Path]:
    install_location = install_location or ""
    reference = str(reference or "").strip().replace("/", "\\")
    if not reference:
        return []
    path = Path(reference)
    if not path.is_absolute():
        path = Path(install_location) / reference
    try:
        path = path.resolve()
    except OSError:
        return []
    if not path.parent.is_dir():
        return []
    stem = path.stem
    candidates: list[Path] = []
    try:
        for entry in os.scandir(path.parent):
            try:
                if not entry.is_file() or Path(entry.name).suffix.lower() not in IMAGE_SUFFIXES:
                    continue
                name = entry.name
                low = name.casefold()
                if (low.startswith(stem.casefold() + ".") or
                        low.startswith(stem.casefold() + "_") or
                        low == path.name.casefold()):
                    candidates.append(Path(entry.path))
            except OSError:
                continue
    except OSError:
        return []
    candidates.sort(key=lambda item: (-_asset_variant_score(item.name, stem), item.name.casefold()))
    if path.is_file() and path not in candidates:
        candidates.insert(0, path)
    return candidates[:3]


def _uwp_logo_search(install_location: str) -> list[Path]:
    if not install_location or not os.path.isdir(install_location):
        return []
    roots = [Path(install_location) / "Assets", Path(install_location)]
    prefixes = ("square44x44logo", "square150x150logo", "applist", "storelogo", "logo")
    result: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_file() or Path(entry.name).suffix.lower() not in IMAGE_SUFFIXES:
                    continue
                low = entry.name.casefold()
                if not any(low.startswith(prefix) for prefix in prefixes):
                    continue
                result.append(Path(entry.path))
            except OSError:
                continue
        if result:
            break
    result.sort(key=lambda item: (-_asset_variant_score(item.name, item.stem), item.name.casefold()))
    return result[:3]


def resolve_sources(app: dict, shortcuts: list[dict] | None = None) -> list[dict]:
    if app.get("kind") == "uwp":
        result: list[dict] = []
        seen = set()
        install_location = app.get("install_location") or ""
        references = list(app.get("uwp_logos") or [])
        for reference in references:
            for path in _uwp_logo_candidates(install_location, reference):
                key = os.path.normcase(str(path))
                if key not in seen:
                    seen.add(key)
                    result.append({"path": str(path), "type": "image"})
        if not result:
            for path in _uwp_logo_search(install_location):
                key = os.path.normcase(str(path))
                if key not in seen:
                    seen.add(key)
                    result.append({"path": str(path), "type": "image"})
        return result

    result = _display_icon_sources(app)
    seen = {os.path.normcase(item["path"]) for item in result}
    for source in _msi_product_icon_source(app):
        key = os.path.normcase(source["path"])
        if key not in seen:
            seen.add(key)
            result.append(source)
    for source in _install_exe_sources(app) + _uninstall_icon_source(app):
        key = os.path.normcase(source["path"])
        if key not in seen:
            seen.add(key)
            result.append(source)
    if shortcuts:
        for source in _shortcut_sources(app, shortcuts):
            key = os.path.normcase(source["path"])
            if key not in seen:
                seen.add(key)
                result.append(source)
    return result


# -------------------------------------------------------------------- worker
def _extract_batch(tasks: list[dict]) -> int:
    if not tasks:
        return 0
    tag = uuid.uuid4().hex
    input_path = ICON_DIR / f".batch-{tag}.json"
    output_path = ICON_DIR / f".batch-{tag}.out.json"
    created = 0
    try:
        input_path.write_text(json.dumps(tasks, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", str(_SCRIPT),
                "-InputFile", str(input_path), "-OutputFile", str(output_path),
            ],
            capture_output=True,
            timeout=150,
            creationflags=wu.CREATE_NO_WINDOW,
        )
        if output_path.exists():
            try:
                results = json.loads(output_path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                results = []
            if isinstance(results, dict):
                results = [results]
            failed = []
            for item in results or []:
                if not isinstance(item, dict):
                    continue
                app_id = str(item.get("id") or "")
                if valid_app_id(app_id) and _remember(app_id):
                    created += 1
                else:
                    failed.append(f"{app_id}:{item.get('reason') or '未生成'}")
            if failed:
                _log("图标提取失败：" + "；".join(failed[:8]))
        if proc.returncode != 0 and created == 0:
            _log(f"图标批处理失败（code {proc.returncode}）：{wu.decode_output(proc.stderr)[:400]}")
    except subprocess.TimeoutExpired:
        _log("图标批处理超时")
    except Exception as exc:
        _log(f"图标批处理异常：{exc}")
    finally:
        for path in (input_path, output_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
    return created


def _warm(apps: list[dict]) -> None:
    missing = []
    for app in apps:
        app_id = str(app.get("id") or "")
        if not valid_app_id(app_id) or version_for(app_id):
            continue
        missing.append(app)
    if not missing:
        return
    _log(f"开始提取 {len(missing)} 个应用图标")
    pending: list[dict] = []
    shortcuts: list[dict] | None = None
    for app in missing:
        try:
            sources = resolve_sources(app)
            if not sources:
                if shortcuts is None:
                    shortcuts = wu.get_shortcut_index()
                sources = _shortcut_sources(app, shortcuts)
        except Exception:
            sources = []
        if not sources:
            continue
        pending.append({
            "id": app["id"],
            "dest": str(icon_path(app["id"])),
            "sources": sources[:8],
        })
    created = 0
    for index in range(0, len(pending), BATCH_SIZE):
        created += _extract_batch(pending[index:index + BATCH_SIZE])
    _log(f"图标提取完成：{created}/{len(pending)}")


def _worker_main(apps: list[dict]) -> None:
    global _worker, _pending
    current = apps
    while True:
        try:
            _warm(current)
        except Exception as exc:
            _log(f"图标工作线程异常：{exc}")
        with _lock:
            if _pending is None:
                _worker = None
                return
            current = _pending
            _pending = None


def warm_async(apps: list[dict]) -> bool:
    """Start (or queue) icon extraction. Returns True when a worker starts."""
    global _worker, _pending
    with _lock:
        if _worker and _worker.is_alive():
            _pending = list(apps)
            return False
        _worker = threading.Thread(
            target=_worker_main, args=(list(apps),), daemon=True, name="softsweep-icons"
        )
        _worker.start()
        return True


_load_existing()
