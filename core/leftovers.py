"""Discover app-specific files, shortcuts and registry entries with confidence levels.

Discovery never deletes anything. Every candidate is re-validated right before
the cleaner touches it. Broad guesses are unchecked by default.
"""
from __future__ import annotations

import concurrent.futures
import os
import re
import time
import winreg
from pathlib import Path

from .winutil import (
    COMMON_START_MENU,
    GENERIC_NAMES,
    is_safe_registry_key,
    LOCAL_APPDATA,
    LOCAL_APPDATA_LOW,
    PROGRAM_DATA,
    PROGRAM_FILES,
    PROGRAM_FILES_X86,
    ROAMING_APPDATA,
    USER_DESKTOP,
    USER_START_MENU,
    app_aliases,
    command_executable,
    compact,
    display_env_path,
    get_shortcut_index,
    is_safe_dir_path,
    is_safe_shortcut_path,
    make_id,
    match_folder_to_app,
    measure_path,
    norm_text,
)

SECTION_DEFS = [
    {"key": "install", "label": "程序文件", "hint": "软件安装目录及卸载程序所在目录"},
    {"key": "userdata", "label": "用户数据", "hint": "当前用户 AppData 中的设置与缓存"},
    {"key": "publicdata", "label": "公共数据", "hint": "ProgramData 中供所有用户使用的数据"},
    {"key": "shortcuts", "label": "快捷方式", "hint": "开始菜单和桌面上的快捷方式"},
    {"key": "registry", "label": "注册表项", "hint": "会先导出 .reg 备份，再删除"},
]

SECTION_ORDER = {s["key"]: i for i, s in enumerate(SECTION_DEFS)}
_SKIP_NAMES = {
    "microsoft", "windows", "windowsapps", "packages", "temp", "cache", "common files",
    "programs", "programdata", "users", "public", "desktop", "documents", "downloads",
    "start menu", "application data", "local settings", "templates", "history",
    "inetcache", "microsoft edge", "microsoft", "windowsapps",
}
_PUB_GENERIC = {
    "inc", "inc.", "ltd", "ltd.", "llc", "co", "co.", "corp", "corp.", "corporation",
    "limited", "company", "technologies", "technology", "software", "systems", "system",
    "digital", "network", "networks", "group", "international", "china", "中国", "有限公司",
    "科技", "网络", "集团", "股份", "工作室", "developer", "developers", "studio",
}

# Common Chinese ↔ English directory aliases (only used for directory matching).
_EXTRA_ALIASES = [
    (("微信", "wechat"), ["wechat", "weixin"]),
    (("企业微信", "wecom", "wxwork"), ["wecom", "wxwork"]),
    (("微信开发者工具", "wechat devtools"), ["wechatwebdevtools", "wechatdevtools"]),
    (("腾讯会议", "tencent meeting", "voov"), ["wemeet", "tencentmeeting"]),
    (("qq",), ["qq", "qqnt"]),
    (("qq音乐", "qqmusic"), ["qqmusic"]),
    (("网易云音乐", "cloudmusic"), ["cloudmusic"]),
    (("钉钉", "dingtalk"), ["dingtalk"]),
    (("飞书", "feishu", "lark"), ["feishu", "lark"]),
    (("百度网盘", "baidu netdisk"), ["baidunetdisk"]),
    (("搜狗输入法", "sogou input"), ["sogouinput"]),
    (("剪映", "capcut"), ["jianying", "capcut"]),
    (("哔哩哔哩", "bilibili"), ["bilibili", "bilibili"]),
    (("爱奇艺", "iqiyi"), ["iqiyi"]),
    (("优酷", "youku"), ["youku"]),
    (("酷狗", "kugou"), ["kugou"]),
    (("酷我", "kuwo"), ["kuwo"]),
    (("迅雷", "thunder", "xunlei"), ["thunder", "xunlei"]),
    (("夸克", "quark"), ["quark"]),
    (("豆包", "doubao"), ["doubao"]),
    (("wps",), ["wps"]),
    (("腾讯", "tencent"), []),  # publisher words are handled separately
    (("网易", "netease"), []),
    (("火绒", "huorong"), ["huorong"]),
    (("钉钉",), ["dingtalk"]),
    (("学习通", "chaoxing"), ["chaoxing"]),
    (("intellij idea community", "intellij idea ce"), ["ideaic"]),
    (("intellij idea ultimate",), ["intellijidea"]),
]

_REGISTRY_BLOCK = {
    "microsoft", "windows", "windows nt", "policies", "classes", "clients",
    "registeredapplications", "odbc", "wow6432node", "wow6432node\\microsoft",
}

RUN_KEYS = [
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_CURRENT_USER, "Run"),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", winreg.HKEY_CURRENT_USER, "RunOnce"),
    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_LOCAL_MACHINE, "Run"),
    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", winreg.HKEY_LOCAL_MACHINE, "RunOnce"),
    ("HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", winreg.HKEY_LOCAL_MACHINE, "Run32"),
    ("HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", winreg.HKEY_LOCAL_MACHINE, "RunOnce32"),
]


_PUBLISHER_TRANSLATIONS = [
    ("腾讯", "tencent"), ("网易", "netease"), ("华为", "huawei"), ("小米", "xiaomi"),
    ("金山", "kingsoft"), ("百度", "baidu"), ("搜狗", "sogou"), ("字节", "bytedance"),
    ("阿里", "alibaba"), ("奇虎", "360"), ("火绒", "huorong"), ("哔哩哔哩", "bilibili"),
    ("爱奇艺", "iqiyi"), ("迅雷", "xunlei"), ("抖音", "douyin"),
]


def _publisher_words(publisher: str) -> set[str]:
    words = set()
    low = (publisher or "").casefold()
    for cjk, latin in _PUBLISHER_TRANSLATIONS:
        if cjk in low:
            words.add(latin)
    for w in norm_text(publisher).split():
        if len(w) >= 3 and w not in _PUB_GENERIC and not w.isdigit():
            words.add(w)
    return words


def _extra_aliases(name: str) -> set[str]:
    low = norm_text(name)
    compact_name = compact(name)
    matched: list[tuple[int, list[str]]] = []
    for needles, extras in _EXTRA_ALIASES:
        for needle in needles:
            n = norm_text(needle)
            if n and (n in low or (len(n) >= 3 and compact(needle) in compact_name)):
                matched.append((len(compact(needle)), extras))
                break
    out: set[str] = set()
    if matched:
        longest = max(m[0] for m in matched)
        for length, extras in matched:
            if length == longest:
                out.update(compact(x) for x in extras)
    return out


_DOTTED_VERSION = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,4}){1,3})(?![\d.])")
_SUFFIX_VERSION = re.compile(r"[a-z\u3400-\u9fff](\d{2,4})$")


def _version_sequences(text: str) -> list[tuple[int, ...]]:
    """Extract full and compact version numbers from a folder/display name."""
    raw = text or ""
    found: list[tuple[int, ...]] = []
    for m in _DOTTED_VERSION.finditer(raw):
        try:
            parts = tuple(int(x) for x in m.group(1).split("."))
        except ValueError:
            continue
        if len(parts) >= 2:
            found.append(parts)
    c = compact(raw)
    m = _SUFFIX_VERSION.search(c)
    if m:
        digits = m.group(1)
        if len(digits) == 2:
            found.append((int(digits),))
        elif len(digits) == 3:
            found.append((int(digits[0]), int(digits[1:])))
        elif len(digits) == 4:
            found.append((int(digits),))
    return found


def _versions_compatible(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    if not a or not b:
        return True
    if len(a) == 1 or len(b) == 1:
        return a[0] == b[0]
    return a[0] == b[0] and a[1] == b[1]


def _app_version_sequences(app: dict) -> list[tuple[int, ...]]:
    seqs = _version_sequences(app.get("name", "")) + _version_sequences(app.get("version", ""))
    return seqs


def _version_conflict(text: str, app: dict) -> bool:
    """True when both sides carry a version and they are clearly different.

    Prevents "Python 3.14" from claiming the "Python 3.11" data folder, or
    "Visual Studio 2022" from claiming an older side-by-side install.
    """
    candidate = _version_sequences(text)
    if not candidate:
        return False
    expected = _app_version_sequences(app)
    if not expected:
        return False
    return not any(
        _versions_compatible(c, e) for c in candidate for e in expected
    )


def _container_resolution(path: Path, app: dict) -> tuple[bool, Path | None]:
    """Detect shared version containers such as %APPDATA%\\Python.

    Returns (is_container, version_specific_child). A container with several
    versioned children is never selected wholesale; only the child matching
    this app's version may be selected.
    """
    if not _app_version_sequences(app):
        return False, None
    base = compact(path.name)
    if not base:
        return False, None
    children = list(_iter_child_dirs(path))[:24]
    versioned = [
        child for child in children
        if compact(child.name).startswith(base) and _version_sequences(child.name)
    ]
    if len(versioned) < 2:
        return False, None
    matches = [child for child in versioned if not _version_conflict(child.name, app)]
    return True, (matches[0] if len(matches) == 1 else None)


def _build_aliases(app: dict) -> set[str]:
    aliases = {compact(a) for a in app.get("aliases", []) if a}
    aliases |= _extra_aliases(app.get("name", ""))
    for key in ("install_location",):
        p = app.get(key)
        if p:
            base = os.path.basename(os.path.normpath(p))
            if base:
                c = compact(base)
                if (len(c) >= 3 and c not in _SKIP_NAMES and c not in GENERIC_NAMES
                        and ("㐀" <= c[0] <= "鿿" or not c.isdigit())):
                    aliases.add(c)
    aliases.discard("")
    return aliases


def _make_item(
    *, kind: str, section: str, path: str, label: str, note: str,
    confidence: str, risk: str, default_selected: bool,
    sel_key: str, value_name: str | None = None,
) -> dict:
    item = {
        "id": make_id("l", sel_key),
        "kind": kind,
        "section": section,
        "label": label,
        "path": path,
        "display_path": display_env_path(path) if kind != "registry" and kind != "registry_value" else path,
        "note": note,
        "confidence": confidence,
        "risk": risk,
        "default_selected": default_selected,
        "bytes": None,
        "size_partial": False,
        "value_name": value_name or "",
    }
    return item


def _add_unique(items: list[dict], seen: set[str], item: dict) -> None:
    key = item["id"]
    if key in seen:
        return
    seen.add(key)
    items.append(item)


def _iter_child_dirs(base: Path):
    if not base.exists():
        return
    try:
        with os.scandir(base) as it:
            for ent in it:
                try:
                    if ent.is_symlink() or not ent.is_dir(follow_symlinks=False):
                        continue
                    if any(part.lower() in {"$recycle.bin", "system volume information"} for part in Path(ent.path).parts):
                        continue
                    yield Path(ent.path)
                except OSError:
                    continue
    except (OSError, PermissionError):
        return


def _folder_has_app_exe(path: Path, aliases: set[str]) -> bool:
    """A strong signal that an uninstaller folder really is the app folder."""
    try:
        with os.scandir(path) as it:
            count = 0
            for ent in it:
                count += 1
                if count > 400:
                    break
                try:
                    if not ent.is_file(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                name = ent.name
                if not name.casefold().endswith(".exe"):
                    continue
                stem = os.path.splitext(name)[0]
                if match_folder_to_app(stem, aliases) >= 2:
                    return True
    except OSError:
        return False
    return False


def _scan_data_root(base: Path, app: dict, aliases: set[str], pub_words: set[str]) -> list[tuple[Path, int, str]]:
    """Shallow scan: direct app folder + one level inside a vendor folder."""
    results: list[tuple[Path, int, str]] = []
    if not base.exists():
        return results
    direct = []
    vendor_dirs = []
    for child in _iter_child_dirs(base):
        name_low = child.name.casefold()
        if name_low in _SKIP_NAMES or name_low == "programs":
            continue
        score = match_folder_to_app(child.name, aliases)
        if score:
            if _version_conflict(child.name, app):
                continue
            shared, exact = _container_resolution(child, app)
            if shared:
                if exact is not None:
                    results.append((exact, 2, "versioned"))
                continue
            direct.append((child, score))
            continue
        c = compact(child.name)
        if (len(c) >= 4 and pub_words and
                any(c == w or c.startswith(w) or w.startswith(c) for w in pub_words if len(w) >= 4)):
            vendor_dirs.append(child)
    for child, score in direct[:6]:
        results.append((child, score, "direct"))
    for vendor in vendor_dirs[:4]:
        for child in _iter_child_dirs(vendor):
            if child.name.casefold() in _SKIP_NAMES:
                continue
            score = match_folder_to_app(child.name, aliases)
            if score and not _version_conflict(child.name, app):
                results.append((child, score, "vendor"))
    return results


def _scan_program_files(aliases: set[str], app: dict, installed_locations: set[str]) -> list[tuple[Path, int]]:
    results: list[tuple[Path, int]] = []
    for base in (PROGRAM_FILES, PROGRAM_FILES_X86):
        for child in _iter_child_dirs(base):
            if child.name.casefold() in _SKIP_NAMES:
                continue
            if child.name.casefold() in {"common files", "windowsapps", "modifiablewindowsapps"}:
                continue
            norm = os.path.normcase(os.path.abspath(child))
            if any(norm == loc or norm.startswith(loc + os.sep) or loc.startswith(norm + os.sep)
                   for loc in installed_locations):
                continue
            score = match_folder_to_app(child.name, aliases)
            if score >= 1 and not _version_conflict(child.name, app):
                shared, exact = _container_resolution(child, app)
                if shared:
                    if exact is not None:
                        results.append((exact, 2))
                    continue
                results.append((child, score))
    return results


def _list_software_children(root, subkey: str, view: int = 0) -> list[str]:
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | view) as key:
            names = []
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
            return names
    except OSError:
        return []


def _registry_key_exists(full_path: str) -> bool:
    import winreg as wr
    upper = full_path.upper()
    if upper.startswith("HKCU\\"):
        root, sub = wr.HKEY_CURRENT_USER, full_path[len("HKCU\\"):]
    elif upper.startswith("HKLM\\"):
        root, sub = wr.HKEY_LOCAL_MACHINE, full_path[len("HKLM\\"):]
    else:
        return False
    try:
        with wr.OpenKey(root, sub, 0, wr.KEY_READ):
            return True
    except OSError:
        return False


def _registry_children_exist(hive_label: str, subkey: str) -> bool:
    import winreg as wr
    root = wr.HKEY_CURRENT_USER if hive_label == "HKCU" else wr.HKEY_LOCAL_MACHINE
    try:
        with wr.OpenKey(root, subkey, 0, wr.KEY_READ):
            return True
    except OSError:
        return False


def _guess_registry_keys(app: dict, aliases: set[str]) -> list[tuple[str, str]]:
    """Return [(full_key_path, match_reason)] for conservative name matches."""
    results: list[tuple[str, str]] = []
    pub_words = _publisher_words(app.get("publisher", ""))
    roots = [
        ("HKCU", winreg.HKEY_CURRENT_USER, "Software", 0),
        ("HKCU", winreg.HKEY_CURRENT_USER, "Software\\WOW6432Node", 0),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, "Software", 0),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, "Software\\WOW6432Node", 0),
    ]
    skip = {"microsoft", "windows", "policies", "classes", "clients", "wow6432node",
            "registeredapplications", "odbc"}
    for hive_label, root, base_sub, _view in roots:
        if not _registry_children_exist(hive_label, base_sub):
            continue
        for child in _list_software_children(root, base_sub)[:500]:
            if child.casefold() in skip:
                continue
            c = compact(child)
            if c in aliases and len(c) >= 4:
                full = f"{hive_label}\\{base_sub}\\{child}"
                if _registry_children_exist(hive_label, base_sub + "\\" + child):
                    results.append((full, f"名称与「{app['name']}」匹配"))
                continue
            if pub_words and any(c == w for w in pub_words):
                child_sub = base_sub + "\\" + child
                for sub in _list_software_children(root, child_sub)[:300]:
                    sc = compact(sub)
                    if sc in aliases and len(sc) >= 4:
                        full = f"{hive_label}\\{child_sub}\\{sub}"
                        if _registry_children_exist(hive_label, child_sub + "\\" + sub):
                            results.append((full, f"位于发布商目录「{child}」下"))
            if len(results) >= 8:
                return results
    # De-duplicate, keep longest unique keys.
    seen = set()
    unique = []
    for path, reason in results:
        key = path.casefold()
        if key not in seen:
            seen.add(key)
            unique.append((path, reason))
    return unique[:8]


def _run_entries(app: dict) -> list[dict]:
    install = app.get("install_location") or ""
    if not install:
        return []
    install_norm = os.path.normcase(os.path.abspath(install)).rstrip("\\")
    aliases = _build_aliases(app)
    app_exe_names = set()
    icon = app.get("display_icon") or ""
    if icon:
        exe = command_executable(icon)
        if exe:
            app_exe_names.add(os.path.basename(exe).casefold())
    uninstall = app.get("uninstall_string") or ""
    if uninstall:
        exe = command_executable(uninstall)
        if exe:
            app_exe_names.add(os.path.basename(exe).casefold())
    found = []
    for reg_path, root, kind in RUN_KEYS:
        sub = reg_path.split("\\", 1)[1]
        try:
            with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        value_name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                    except OSError:
                        break
                    cmd = str(value) if value is not None else ""
                    if not cmd:
                        continue
                    exe = command_executable(cmd)
                    cmd_norm = os.path.normcase(os.path.abspath(exe)) if exe and os.path.isabs(exe) else ""
                    inside = bool(cmd_norm and (cmd_norm == install_norm or cmd_norm.startswith(install_norm + os.sep)))
                    name_hit = compact(value_name) in aliases or (
                        exe and os.path.basename(exe).casefold() in app_exe_names
                    )
                    if inside or (name_hit and exe):
                        found.append({
                            "key_path": reg_path,
                            "value_name": value_name,
                            "command": cmd,
                            "inside": inside,
                        })
                    if len(found) >= 6:
                        return found
        except OSError:
            continue
    return found


def discover_leftovers(app: dict, all_apps: list[dict] | None = None) -> dict:
    start = time.monotonic()
    items: list[dict] = []
    seen: set[str] = set()
    notices: list[str] = []
    aliases = _build_aliases(app)
    pub_words = _publisher_words(app.get("publisher", ""))
    install = app.get("install_location") or ""
    install_abs = os.path.abspath(install) if install else ""
    installed_locations = set()
    for other in all_apps or []:
        if other.get("id") == app.get("id"):
            continue
        loc = other.get("install_location")
        if loc:
            installed_locations.add(os.path.normcase(os.path.abspath(loc)).rstrip("\\"))

    def is_other_app_path(path: str) -> bool:
        n = os.path.normcase(os.path.abspath(path)).rstrip("\\")
        for loc in installed_locations:
            if n == loc or n.startswith(loc + os.sep) or loc.startswith(n + os.sep):
                return True
        return False

    is_uwp = app.get("kind") == "uwp"

    # Program files ---------------------------------------------------------
    if not is_uwp and install_abs and os.path.isdir(install_abs):
        if is_safe_dir_path(install_abs, trusted=True) and not is_other_app_path(install_abs):
            items.append(_make_item(
                kind="dir", section="install",
                path=install_abs,
                label="安装目录",
                note="软件主程序及附带文件；官方卸载后仍存在才会被清理",
                confidence="high", risk="normal", default_selected=True,
                sel_key="dir|" + os.path.normcase(install_abs),
            ))
        else:
            notices.append("安装目录位于受保护或共享位置，已跳过自动清理")
    elif not is_uwp and not install_abs:
        guess = _scan_program_files(aliases, app, installed_locations)
        for path, score in guess[:3]:
            if is_safe_dir_path(path, trusted=True):
                items.append(_make_item(
                    kind="dir", section="install", path=str(path),
                    label="疑似安装目录（注册表未登记）",
                    note="根据名称推断，请务必确认该目录属于此软件",
                    confidence="medium", risk="high", default_selected=False,
                    sel_key="dir|" + os.path.normcase(str(path)),
                ))

    # Uninstaller's own folder, if it is not inside the install folder.
    if not is_uwp:
        uninstall_cmd = app.get("uninstall_string") or ""
        exe = command_executable(uninstall_cmd)
        if exe and os.path.isabs(exe) and os.path.exists(exe):
            exe_dir = os.path.dirname(exe)
            if exe_dir and (
                not install_abs or
                os.path.normcase(exe_dir) != os.path.normcase(install_abs)
            ):
                if is_safe_dir_path(exe_dir, trusted=True) and not is_other_app_path(exe_dir):
                    score = match_folder_to_app(os.path.basename(exe_dir), aliases)
                    exe_match = _folder_has_app_exe(Path(exe_dir), aliases)
                    if score or exe_match or "package cache" not in exe_dir.casefold():
                        items.append(_make_item(
                            kind="dir", section="install", path=exe_dir,
                            label="卸载程序目录",
                            note="卸载程序所在目录，通常包含软件残留文件",
                            confidence="high" if exe_match else "medium",
                            risk="caution",
                            default_selected=bool((score >= 1 or exe_match) and not install_abs),
                            sel_key="dir|" + os.path.normcase(exe_dir),
                        ))

    # UWP app data ----------------------------------------------------------
    if is_uwp:
        family = app.get("package_family_name") or ""
        if family:
            pkg = LOCAL_APPDATA / "Packages" / family
            if pkg.exists() and is_safe_dir_path(str(pkg), trusted=True):
                items.append(_make_item(
                    kind="dir", section="userdata", path=str(pkg),
                    label="商店应用数据",
                    note="应用设置、缓存和本地账号数据；会移入回收站",
                    confidence="high", risk="caution", default_selected=True,
                    sel_key="dir|" + os.path.normcase(str(pkg)),
                ))
        notices.append("商店应用的安装目录由 Windows 保护，不会自动删除，仅清理用户数据")

    # AppData / ProgramData ------------------------------------------------
    if not is_uwp:
        roots = [
            (LOCAL_APPDATA, "userdata"),
            (ROAMING_APPDATA, "userdata"),
            (LOCAL_APPDATA_LOW, "userdata"),
            (LOCAL_APPDATA / "Programs", "install"),
            (PROGRAM_DATA, "publicdata"),
        ]
        seen_paths = {os.path.normcase(item["path"]) for item in items if item["kind"] == "dir"}
        for base, section in roots:
            try:
                candidates = _scan_data_root(base, app, aliases, pub_words)
            except (OSError, PermissionError):
                continue
            for path, score, how in candidates:
                norm = os.path.normcase(str(path))
                if norm in seen_paths:
                    continue
                if is_other_app_path(str(path)):
                    continue
                if not is_safe_dir_path(str(path), trusted=True):
                    continue
                if any(part.lower() in {"microsoft", "windowsapps", "common files"} for part in path.parts):
                    continue
                confidence = "high" if score >= 2 else "medium"
                default = score >= 2
                note = ("名称与软件匹配的用户数据目录" if section == "userdata"
                        else "名称与软件匹配的公共数据目录")
                items.append(_make_item(
                    kind="dir", section=section, path=str(path),
                    label="用户数据" if section == "userdata" else "公共数据",
                    note=note + "；可能包含登录状态、设置或缓存，移入回收站可恢复",
                    confidence=confidence, risk="caution", default_selected=default,
                    sel_key="dir|" + norm,
                ))
                seen_paths.add(norm)
                if len([i for i in items if i["section"] in ("userdata", "publicdata", "install")]) >= 18:
                    break

    # Shortcuts -------------------------------------------------------------
    if not is_uwp:
        try:
            shortcuts = get_shortcut_index()
        except Exception:
            shortcuts = []
        count = 0
        for sc in shortcuts:
            path = sc.get("path") or ""
            if not is_safe_shortcut_path(path):
                continue
            target = sc.get("target") or ""
            target_hit = False
            if install_abs and target:
                try:
                    tn = os.path.normcase(os.path.abspath(target))
                    target_hit = tn.startswith(os.path.normcase(install_abs.rstrip("\\")) + os.sep)
                except (OSError, ValueError):
                    target_hit = False
            stem = Path(path).stem
            name_score = match_folder_to_app(stem, aliases) >= 2
            if not target_hit and _version_conflict(stem, app):
                continue
            if not (target_hit or name_score):
                continue
            if is_other_app_path(path):
                continue
            items.append(_make_item(
                kind="shortcut", section="shortcuts", path=path,
                label="快捷方式",
                note="开始菜单或桌面快捷方式",
                confidence="high" if target_hit else "medium", risk="normal",
                default_selected=True,
                sel_key="shortcut|" + os.path.normcase(path),
            ))
            count += 1
            if count >= 12:
                break

    # Registry --------------------------------------------------------------
    if not is_uwp:
        for key in app.get("uninstall_keys", []) or [app.get("uninstall_key")]:
            if not key or not is_safe_registry_key(key) or not _registry_key_exists(key):
                continue
            label = "卸载注册项"
            confidence = "high"
            note = "软件在「已安装应用」中的登记信息；官方卸载后通常会自动移除"
            items.append(_make_item(
                kind="registry", section="registry", path=key,
                label=label, note=note, confidence=confidence, risk="caution",
                default_selected=True,
                sel_key="registry|" + key.casefold(),
            ))
        for key, reason in _guess_registry_keys(app, aliases):
            items.append(_make_item(
                kind="registry", section="registry", path=key,
                label="软件设置注册表项",
                note=reason + "，可能保存设置；默认不勾选，删除前会导出备份",
                confidence="medium", risk="high", default_selected=False,
                sel_key="registry|" + key.casefold(),
            ))
        for run in _run_entries(app):
            key_path = run["key_path"]
            value_name = run["value_name"]
            items.append(_make_item(
                kind="registry_value", section="registry", path=key_path,
                value_name=value_name,
                label="开机启动项",
                note=f"启动项「{value_name}」指向该软件；删除前会备份整个启动项键",
                confidence="high" if run["inside"] else "medium",
                risk="caution", default_selected=bool(run["inside"]),
                sel_key=f"registry_value|{key_path.casefold()}|{value_name.casefold()}",
            ))

    # Deduplicate by id and drop dirs that contain another safer item? Keep as-is.
    unique: dict[str, dict] = {}
    for item in items:
        unique.setdefault(item["id"], item)
    items = list(unique.values())
    items.sort(key=lambda i: (
        SECTION_ORDER.get(i["section"], 99),
        0 if i["default_selected"] else 1,
        -(i["bytes"] or 0),
        i["label"],
    ))

    # Measure selected candidates in parallel (bounded).
    to_measure = [i for i in items if i["kind"] != "registry"]
    def measure(item):
        if item["kind"] == "registry":
            return
        res = measure_path(item["path"], max_seconds=4.5, max_entries=90_000)
        item["bytes"] = res.get("bytes")
        item["size_partial"] = bool(res.get("partial"))
    if to_measure:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="leftover-size") as pool:
            list(pool.map(measure, to_measure))

    selected_bytes = sum(
        (i.get("bytes") or 0) for i in items if i["default_selected"] and i["kind"] != "registry"
    )
    all_bytes = sum((i.get("bytes") or 0) for i in items if i["kind"] != "registry")
    warnings = list(notices)
    if any(not i["default_selected"] for i in items if i["risk"] == "high"):
        warnings.append("标记为「请确认」的项目默认不勾选，请自行判断后再选择")
    warnings.append("文档、下载和个人图片目录中的文件不会自动纳入，以免误删用户资料")

    return {
        "app_id": app.get("id"),
        "app_name": app.get("name"),
        "items": items,
        "sections": SECTION_DEFS,
        "selected_bytes": selected_bytes,
        "all_bytes": all_bytes,
        "notice": warnings,
        "scanned_at": time.time(),
        "duration": round(time.monotonic() - start, 2),
        "is_admin": None,
    }
