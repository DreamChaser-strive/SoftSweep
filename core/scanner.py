"""Installed-software inventory for classic Win32 apps and Microsoft Store/UWP apps."""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import threading
import time
import traceback
import winreg
from datetime import datetime
from pathlib import Path

from . import icons as icon_store
from .winutil import (
    APP_DIR,
    LOCAL_APPDATA,
    LOCAL_APPDATA_LOW,
    PROGRAM_DATA,
    PROGRAM_FILES,
    PROGRAM_FILES_X86,
    WINDOWS_DIR,
    app_aliases,
    command_executable,
    compact,
    decode_output,
    display_env_path,
    is_admin,
    is_safe_dir_path,
    make_id,
    match_folder_to_app,
    measure_path,
    norm_text,
    run_powershell,
    system_drive_is,
)

CATEGORY_DEFS = [
    ("dev", "开发工具", "#5B61D6"),
    ("office", "办公效率", "#B87418"),
    ("network", "浏览器与网络", "#15826B"),
    ("comm", "通讯社交", "#138D9B"),
    ("media", "影音图像", "#BF4B7C"),
    ("game", "游戏娱乐", "#7B5BD6"),
    ("security", "安全防护", "#B83A32"),
    ("utility", "实用工具", "#47708C"),
    ("system", "系统组件", "#8B6A38"),
    ("driver", "驱动程序", "#6C7A73"),
    ("runtime", "运行库", "#68757E"),
    ("other", "其他", "#7C8790"),
]
CATEGORY_MAP = {key: {"key": key, "label": label, "color": color} for key, label, color in CATEGORY_DEFS}
PROTECTED_CATEGORIES = {"system", "driver", "runtime"}

SOURCE_LABELS = {"thirdparty": "下载安装", "store": "应用商店", "system": "系统内置"}
_RUNTIME_DIR = os.path.normcase(os.path.dirname(os.path.abspath(sys.executable))) if sys.executable else ""


def _resolve_install_location(values: dict, name: str, publisher: str) -> str:
    """Recover the install folder for package-based installers (e.g. Python bundles).

    Only well-known, self-registered locations are used; this never guesses from
    a display name alone.
    """
    version = ""
    provider = _safe_str(values.get("BundleProviderKey"))
    m = re.search(r"CPython-(\d+\.\d+)", provider, re.IGNORECASE)
    if not m and "python" in (publisher or "").casefold():
        m = re.search(r"Python\s+(\d+\.\d+)", name, re.IGNORECASE)
    if not m:
        return ""
    version = m.group(1)
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for wow in (0, getattr(winreg, "KEY_WOW64_64KEY", 0x100)):
            try:
                with winreg.OpenKey(
                    root, rf"Software\Python\PythonCore\{version}\InstallPath",
                    0, winreg.KEY_READ | wow,
                ) as key:
                    location = _safe_str(winreg.QueryValueEx(key, "")[0])
            except OSError:
                continue
            if location:
                location = os.path.expandvars(location.strip().strip('"'))
                if os.path.isabs(location) and os.path.isdir(location):
                    return location
    return ""


_UPWARD_GENERIC = {
    "app", "apps", "bin", "bin64", "x64", "x86", "current", "main", "resources",
    "uninstall", "uninst", "utility", "application", "code", "root", "release",
    "icon", "icons", "assets", "res", "resource", "data", "images", "image",
    "locales", "locale", "plugin", "plugins", "extension", "extensions",
    "cache", "caches", "log", "logs", "temp", "tmp", "dist", "exe", "win32",
}
_PROBE_DENY_NAMES = _UPWARD_GENERIC | {
    "program files", "program files (x86)", "windows", "users", "user",
    "programdata", "appdata", "packages", "common files", "downloads",
    "documents", "desktop", "pictures", "videos", "music",
}
_LOCAL_CHILD_CONTAINERS = {
    "programs", "packages", "temp", "microsoft", "publishers", "comms",
    "connected devices", "crashdumps", "iconcache", "asset cache", "history",
    "placeholderdata", "peerdist", "deployment",
}
_VERSION_DIR_RE = re.compile(r"^\d+(\.\d+){1,3}([-.][0-9a-z]+)*$", re.IGNORECASE)


def _looks_like_app_leaf(folder: str, aliases: set[str] | None = None) -> bool:
    """Refuse container roots so a size probe never counts a whole vendor tree."""
    try:
        parts = Path(os.path.abspath(folder)).parts
    except (OSError, ValueError):
        return False
    if len(parts) < 2:
        return False
    name = parts[-1].casefold()
    if name in _PROBE_DENY_NAMES or len(name) < 2:
        return False
    named_match = bool(aliases) and match_folder_to_app(parts[-1], aliases) >= 2
    for root in (PROGRAM_FILES, PROGRAM_FILES_X86, LOCAL_APPDATA, LOCAL_APPDATA_LOW,
                 PROGRAM_DATA, WINDOWS_DIR):
        root_parts = Path(root).parts
        if parts[: len(root_parts)] != root_parts:
            continue
        if len(parts) == len(root_parts):
            return False
        if len(parts) > len(root_parts) + 1:
            continue
        # The folder is a direct child of a well-known root.
        if root in (PROGRAM_DATA, WINDOWS_DIR, LOCAL_APPDATA_LOW):
            return False
        if root == LOCAL_APPDATA:
            # %LOCALAPPDATA%\<App> is the normal single-installer layout, but
            # shared sub-roots must never be measured as one product.
            return name not in _LOCAL_CHILD_CONTAINERS
        # Program Files children are usually vendor folders.
        return named_match
    return True


def _normalise_probe_folder(exe: str) -> str:
    """Walk out of bin/app/version sub-folders to the folder that holds the app."""
    folder = os.path.dirname(os.path.abspath(exe))
    for _ in range(3):
        parent = os.path.dirname(folder)
        if not parent or parent == folder:
            break
        name = os.path.basename(folder).casefold()
        if name in _UPWARD_GENERIC or _VERSION_DIR_RE.match(name):
            folder = parent
            continue
        break
    return folder


def _inferred_program_folder(raw: dict, aliases: set[str] | None = None) -> str:
    """Program folder inferred from the app's own exe paths, for size counting only.

    This value is never used as a cleanup target: uninstall and cleanup keep relying
    on the registry InstallLocation plus the audited leftover scanner.
    """
    for command in (raw.get("display_icon"), raw.get("quiet_uninstall_string"), raw.get("uninstall_string")):
        exe = command_executable(_safe_str(command))
        if not exe:
            continue
        exe = os.path.expandvars(exe)
        if not os.path.isabs(exe) or not os.path.exists(exe):
            continue
        folder = _normalise_probe_folder(exe)
        if not _looks_like_app_leaf(folder, aliases):
            continue
        if not is_safe_dir_path(folder, trusted=True):
            continue
        return folder
    return ""


def _validate_size_probes(apps: list[dict]) -> None:
    """Drop probes that would count a shared container instead of one product."""
    known = [
        os.path.normcase(os.path.abspath(app["install_location"])).rstrip(os.sep)
        for app in apps if app.get("install_location")
    ]
    usage: dict[str, int] = {}
    for app in apps:
        probe = app.get("size_probe_path") or ""
        if not probe:
            continue
        n = os.path.normcase(os.path.abspath(probe)).rstrip(os.sep)
        if any(other != n and (other.startswith(n + os.sep) or n.startswith(other + os.sep))
               for other in known):
            app["size_probe_path"] = ""
            continue
        usage[n] = usage.get(n, 0) + 1
    for app in apps:
        if app.get("protected"):
            continue
        probe = app.get("size_probe_path") or ""
        if not probe:
            if (app.get("install_location") and not app.get("location_exists")
                    and app.get("size_state") == "unknown"):
                app["size_state"] = "missing"
            continue
        n = os.path.normcase(os.path.abspath(probe)).rstrip(os.sep)
        if usage.get(n, 0) >= 4:
            app["size_probe_path"] = ""
            continue
        if app.get("size_state") in ("unknown", "estimated"):
            app["size_state"] = "computing"


# --------------------------------------------------------------- classification
_DEV = [
    "visual studio", "vs code", "visual studio code", "jetbrains", "intellij", "pycharm",
    "webstorm", "goland", "clion", "datagrip", "phpstorm", "rider", "android studio",
    "sublime text", "notepad++", "eclipse", "sourcetree", "github desktop",
    "docker", "postman", "insomnia", "navicat", "dbeaver", "heidisql", "mysql",
    "sql server", "postgresql", "mongodb", "redis", "python", "node.js", "nodejs",
    "java se development", "jdk", "cuda", "anaconda", "miniconda", "unity",
    "unreal engine", "godot", "cmake", "msbuild", "maven", "gradle", "xshell",
    "xftp", "winscp", "xampp", "wamp", "laragon", "dev-c++", "code::blocks",
    "rustup", "golang", "staruml", "emacs", "github", "gitlab", "colab",
    "jupyter", "ollama", "llama", "codex", "cursor", "windsurf", "trae", "codebuddy",
    "nvm", "msys2", "tomcat", "java(tm) se development", "apifox", "antigravity",
    "qoder", "workbuddy", "cc switch", "mockingbot", "postman", "openai",
]
_OFFICE = [
    "microsoft office", "office 365", "microsoft 365", "microsoft word", "microsoft excel",
    "microsoft powerpoint", "microsoft outlook", "microsoft onenote", "wps office", "wps",
    "officeplus", "office 工具", "adobe acrobat", "acrobat reader", "foxit", "福昕",
    "pdf", "notion", "obsidian", "evernote", "印象笔记", "有道云笔记", "xmind",
    "mindmaster", "亿图", "edraw", "visio", "endnote", "mathtype", "typora",
    "zotero", "calibre", "石墨文档", "腾讯文档", "钉钉文档", "microsoft project",
    "microsoft visio", "扫描全能王", "camscanner",
]
_NETWORK = [
    "google chrome", "chrome", "mozilla firefox", "firefox", "microsoft edge",
    "opera", "brave", "vivaldi", "safari", "浏览器", "browser",
    "360安全浏览器", "360极速浏览器", "qq浏览器", "搜狗浏览器", "猎豹浏览器", "傲游",
    "maxthon", "tor browser", "internet download manager", "idm", "迅雷", "thunder",
    "aria2", "motrix", "free download manager", "百度网盘", "baidu netdisk",
    "阿里云盘", "夸克网盘", "onedrive", "dropbox", "google drive", "坚果云",
    "nutstore", "clash", "v2ray", "openvpn", "wireguard", "vpn", "代理",
    "网盘", "ftp", "filezilla", "termius", "ssh", "浏览器插件", "浏览器扩展",
    "夸克", "quark",
]
_COMM = [
    "wechat", "微信", "wecom", "企业微信", "telegram", "whatsapp", "discord",
    "slack", "zoom", "skype", "飞书", "feishu", "lark", "dingtalk", "钉钉",
    "tencent meeting", "腾讯会议", "voov", "popo", "signal", "messenger",
    "wechatwork", "腾讯qq", "qqnt",
]
_MEDIA = [
    "vlc", "potplayer", "mpc-hc", "mpc-be", "kmplayer", "gom player", "爱奇艺",
    "iqiyi", "腾讯视频", "优酷", "youku", "bilibili", "哔哩哔哩", "网易云音乐",
    "cloudmusic", "qq音乐", "酷狗", "kugou", "酷我", "kuwo", "spotify", "itunes",
    "foobar2000", "aimp", "photoshop", "premiere", "illustrator", "after effects",
    "lightroom", "audition", "davinci resolve", "blender", "gimp", "obs studio",
    "剪映", "capcut", "格式工厂", "formatfactory", "handbrake", "filmora",
    "会声会影", "coreldraw", "autocad", "3ds max", "maya", "zbrush", "cinema 4d",
    "wallpaper engine", "网易云", "酷我音乐", "暴风影音", "影音",
    "音乐", "视频", "播放器", "图片", "照片", "camera", "相册", "媒体播放器",
]
_GAME = [
    "steam", "epic games", "epicgames", "wegame", "腾讯游戏", "网易游戏",
    "ubisoft", "uplay", "battle.net", "blizzard", "ea app", "gog galaxy",
    "xbox", "minecraft", "我的世界", "原神", "genshin", "英雄联盟",
    "league of legends", "valorant", "dota", "counter-strike", "csgo", "cs2",
    "和平精英", "崩坏", "星穹铁道", "永劫无间", "逆水寒", "梦幻西游", "穿越火线",
    "地下城与勇士", "游戏", "solitaire", "纸牌", "roblox", "育碧",
]
_SECURITY = [
    "360安全卫士", "360杀毒", "360 total security", "奇安信", "火绒", "huorong",
    "腾讯电脑管家", "电脑管家", "金山毒霸", "毒霸", "antivirus", "anti-virus",
    "kaspersky", "norton", "mcafee", "eset", "bitdefender", "avast", "avg",
    "malwarebytes", "adaware", "windows defender", "安全卫士", "杀毒", "安全防护",
    "渗透测试", "wireshark", "burp suite", "fiddler",
]
_DRIVER_EXCLUDE = [
    "驱动精灵", "驱动人生", "driver booster", "driver easy", "驱动大师",
    "驱动总裁", "360驱动", "driverpack",
]
_RUNTIME = [
    "visual c++", "redistributable", "microsoft .net", ".net runtime",
    ".net desktop runtime", ".net host", "dotnet", "directx", "webview2",
    "windows app runtime", "windows desktop runtime", "windows software development kit",
    "windows sdk", "java runtime environment", "jre", "windows driver package",
    "microsoft edge update", "update health tools", "windows subsystem for linux",
    "wsl", "windows app sdk", "microsoft xna", "openal", "physx", "vc redist",
    "windows codec", "heif image extension", "hevc video extension", "av1 video extension",
]
_SYSTEM = [
    "windows feature", "windows update", "servicing stack", "language pack",
    "语言包", "microsoft windows", "windows security", "microsoft defender",
    "windows 安全", "系统组件", "windows 组件", "windows pc health check",
    "windows 小组件", "windows widgets", "microsoft edge webview",
    "windows 终端", "windows subsystem", "directx",
]
_DEV_WORD = re.compile(r"(?<![a-z0-9])(git|vim)(?![a-z0-9])", re.I)
_UTILITY = [
    "7-zip", "7zip", "winrar", "winzip", "bandizip", "peazip", "everything",
    "listary", "utools", "quicklook", "snipaste", "sharex", "截图", "截图工具",
    "输入法", "搜狗输入法", "百度输入法", "微软拼音", "qq拼音", "todesk", "teamviewer",
    "anydesk", "sunlogin", "向日葵", "virtualbox", "vmware", "parallels",
    "模拟器", "雷电模拟器", "mumu", "逍遥模拟器", "bluestacks", "夜神", "ccleaner",
    "dism++", "geek uninstaller", "鲁大师", "cpu-z", "gpu-z", "aida64",
    "crystaldiskinfo", "crystaldiskmark", "hwinfo", "驱动精灵", "driver booster",
    "驱动人生", "directx修复", "图吧工具箱", "translucenttb", "startallback",
    "start11", "wiztree", "treesize", "spacesniffer", "unlocker", "lockhunter",
    "notepad", "记事本", "计算器", "calculator", "时钟", "闹钟", "录音机",
    "相机", "camera", "地图", "maps", "天气", "weather", "资讯", "news",
    "便笺", "sticky notes", "手机连接", "phone link", "your phone", "获取帮助",
    "反馈中心", "使用技巧", "快速助手", "quick assist", "terminal", "终端",
    "命令提示符", "远程桌面", "remote desktop", "microsoft store",
    "应用安装程序", "清理", "解压", "压缩", "硬件检测", "系统工具", "截图录屏",
    "远程控制", "power toys", "powertoys", "huawei", "hms core", "appgallery",
    "hw osd", "pc克隆", "个人中心", "remoteclient", "手机克隆", "华为手机助手",
    "uu远程", "翻译", "有道", "豆包", "grok", "gemini", "claude", "copilot",
    "kimi", "通义", "文心一言", "ima", "学习通", "番茄todo", "安装助手", "易升",
    "夸克", "青简", "todos", "journal", "whiteboard", "学习", "课程",
]
_DRIVER_STRONG = re.compile(r"\bdriver\b|驱动|chipset|realtek|nvidia|radeon|graphics driver", re.I)
_QQ_WORD = re.compile(r"(?<![a-z0-9])qq(?![a-z0-9])", re.I)
_EDGE_WORD = re.compile(r"(?<![a-z0-9])edge(?![a-z0-9])(?!\s*webview)", re.I)
_GAME_WORD = re.compile(r"(?<![a-z0-9])game(?![a-z0-9])", re.I)
_TIM_WORD = re.compile(r"(?<![a-z0-9])tim(?![a-z0-9])", re.I)


def _has(hay: str, patterns: list[str]) -> bool:
    return any(p in hay for p in patterns)


def classify(name: str, publisher: str = "") -> str:
    hay = (name + " " + publisher).casefold()
    if _DRIVER_STRONG.search(hay) and not _has(hay, _DRIVER_EXCLUDE):
        return "driver"
    if _has(hay, _RUNTIME):
        return "runtime"
    if _has(hay, _SYSTEM):
        return "system"
    if _has(hay, _SECURITY):
        return "security"
    if _EDGE_WORD.search(hay) or _has(hay, _NETWORK):
        return "network"
    if _has(hay, _MEDIA):
        return "media"
    if _has(hay, _GAME) or _GAME_WORD.search(hay):
        return "game"
    if _has(hay, _DEV) or _DEV_WORD.search(hay):
        return "dev"
    if _has(hay, _OFFICE):
        return "office"
    if _has(hay, _COMM) or _QQ_WORD.search(hay) or _TIM_WORD.search(hay):
        return "comm"
    if _has(hay, _UTILITY):
        return "utility"
    return "other"


def _category_for_uwp(name: str, friendly: str) -> str:
    hay = (name + " " + friendly).casefold()
    if any(x in hay for x in ("photos", "camera", "zunemusic", "zunevideo", "media player",
                              "clipchamp", "照片", "相机", "媒体播放器", "电影")):
        return "media"
    if any(x in hay for x in ("xbox", "solitaire", "game", "游戏", "纸牌", "minecraft")):
        return "game"
    if any(x in hay for x in ("office", "mail", "calendar", "officehub", "outlook",
                              "word", "excel", "powerpoint", "windowscommunicationsapps",
                              "todos", "journal")):
        return "office"
    if any(x in hay for x in ("teams", "people", "whatsapp", "phone", "手机连接")):
        return "comm"
    if any(x in hay for x in ("terminal", "devhome", "developer", "winget")):
        return "dev"
    if any(x in hay for x in ("weather", "news", "bing")):
        return "media"
    return "utility"


UWP_FRIENDLY = {
    "Microsoft.WindowsCalculator": "计算器",
    "Microsoft.Windows.Photos": "照片",
    "Microsoft.WindowsCamera": "相机",
    "Microsoft.WindowsStore": "Microsoft Store",
    "Microsoft.DesktopAppInstaller": "应用安装程序",
    "Microsoft.WindowsNotepad": "记事本",
    "Microsoft.Paint": "画图",
    "Microsoft.Paint3D": "画图 3D",
    "Microsoft.ScreenSketch": "截图工具",
    "Microsoft.WindowsTerminal": "Windows 终端",
    "Microsoft.WindowsAlarms": "时钟",
    "Microsoft.BingWeather": "天气",
    "Microsoft.BingNews": "资讯",
    "Microsoft.BingFinance": "财经",
    "Microsoft.BingSports": "体育",
    "Microsoft.MicrosoftSolitaireCollection": "微软纸牌",
    "Microsoft.XboxApp": "Xbox",
    "Microsoft.GamingApp": "Xbox",
    "Microsoft.XboxGamingOverlay": "Xbox Game Bar",
    "Microsoft.ZuneMusic": "媒体播放器",
    "Microsoft.ZuneVideo": "电影和电视",
    "Microsoft.MicrosoftStickyNotes": "便笺",
    "Microsoft.WindowsMaps": "地图",
    "Microsoft.People": "人脉",
    "Microsoft.MicrosoftOfficeHub": "Microsoft 365",
    "Microsoft.GetHelp": "获取帮助",
    "Microsoft.Getstarted": "使用技巧",
    "Microsoft.WindowsFeedbackHub": "反馈中心",
    "Microsoft.WindowsSoundRecorder": "录音机",
    "Microsoft.YourPhone": "手机连接",
    "Microsoft.PowerAutomateDesktop": "Power Automate",
    "Microsoft.Windows.DevHome": "开发人员主页",
    "MicrosoftCorporationII.MicrosoftFamily": "Microsoft Family",
    "Microsoft.MicrosoftPCManager": "Microsoft PC Manager",
    "Clipchamp.Clipchamp": "Clipchamp",
    "Microsoft.Windows.PhotosMicrosoft": "照片",
    "5319275A.WhatsAppDesktop": "WhatsApp",
    "SpotifyAB.SpotifyMusic": "Spotify",
    "MSTeams": "Microsoft Teams",
    "MicrosoftTeams": "Microsoft Teams",
    "microsoft.windowscommunicationsapps": "邮件和日历",
    "Microsoft.WindowsMaps": "地图",
    "Microsoft.People": "人脉",
    "Microsoft.Windows.DevHome": "开发人员主页",
}

UWP_HIDE_PREFIXES = (
    "Microsoft.Windows.ShellExperienceHost",
    "Microsoft.Windows.StartMenuExperienceHost",
    "Microsoft.Windows.Search",
    "Microsoft.Windows.CloudExperienceHost",
    "Microsoft.AAD.BrokerPlugin",
    "Microsoft.AccountsControl",
    "Microsoft.LockApp",
    "Microsoft.Win32WebViewHost",
    "Microsoft.CredDialogHost",
    "Microsoft.ECApp",
    "Microsoft.Windows.ContentDeliveryManager",
    "Microsoft.Windows.PinningConfirmationDialog",
    "Microsoft.Windows.AssignedAccessLockApp",
    "Microsoft.Windows.PeopleExperienceHost",
    "Microsoft.Windows.XGpuEjectDialog",
    "Microsoft.Windows.FilePicker",
    "Microsoft.Windows.PrintQueueActionCenter",
    "Microsoft.Windows.CapturePicker",
    "Microsoft.Windows.SecHealthUI",
    "Microsoft.Windows.SecureAssessmentBrowser",
    "Microsoft.Windows.AppRep.ChxApp",
    "Microsoft.UI.Xaml",
    "Microsoft.VCLibs",
    "Microsoft.NET.Native",
    "Microsoft.Services.Store.Engagement",
    "MicrosoftWindows.",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.GamingServices",
    "Microsoft.StorePurchaseApp",
    "Microsoft.WindowsAppRuntime",
    "Microsoft.Winget.Source",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.WindowsStore",
    "Microsoft.SECHealthUI",
    "Microsoft.Windows.Photos.DLC",
    "Microsoft.WinAppRuntime",
    "MicrosoftCorporationII.WinAppRuntime",
    "Microsoft.MixedReality.Portal",
    "Microsoft.BioEnrollment",
    "Windows.CBSPreview",
    "WinRAR.ShellExtension",
    "PDFShellExt",
    "QQExtension",
    "BaiduNetdisk.DesktopSyncClient",
    "Microsoft.XboxGameOverlay",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.GamingServices",
    "Microsoft.AsyncTextService",
    "Microsoft.MicrosoftEdgeDevToolsClient",
    "Microsoft.Windows.Apprep.ChxApp",
    "Microsoft.Windows.NarratorQuickStart",
    "Microsoft.Windows.ParentalControls",
    "Microsoft.XboxGameCallableUI",
    "windows.immersivecontrolpanel",
    "Windows.PrintDialog",
    "Microsoft.Windows.OOBENetworkCaptivePortal",
    "Microsoft.Windows.OOBENetworkConnectionFlow",
    "Microsoft.SecHealthUI",
    "Microsoft.VP9VideoExtensions",
    "Microsoft.WebpImageExtension",
    "Microsoft.HEIFImageExtension",
    "Microsoft.HEVCVideoExtension",
    "Microsoft.WebMediaExtensions",
    "Microsoft.AV1VideoExtension",
    "Microsoft.AVCEncoderVideoExtension",
    "Microsoft.MPEG2VideoExtension",
    "Microsoft.RawImageExtension",
    "Microsoft.ApplicationCompatibilityEnhancements",
    "Microsoft.LanguageExperiencePack",
    "Microsoft.MicrosoftEdge.Stable",
    "Microsoft.Edge.GameAssist",
    "Microsoft.WidgetsPlatformRuntime",
    "Microsoft.StartExperiencesApp",
    "Microsoft.Office.ActionsServer",
    "Microsoft.Office.OneNoteVirtualPrinter",
    "Microsoft.Ink.Handwriting",
    "Microsoft.VisualStudioCode",
    "wpsappext",
    "ksystemsharehost",
    "WeixinShare",
    "WorkBuddyShareTarget",
    "3AD8A913.",
)

UWP_PROTECTED = {
    "Microsoft.WindowsStore": "Microsoft Store 是系统应用入口",
    "Microsoft.DesktopAppInstaller": "应用安装程序（winget）为系统组件",
    "Microsoft.StorePurchaseApp": "应用商店购买组件",
    "Microsoft.Windows.SecHealthUI": "Windows 安全中心组件",
    "Microsoft.HEIFImageExtension": "系统图像解码组件，移除后部分图片无法预览",
    "Microsoft.HEVCVideoExtension": "系统视频解码组件",
    "Microsoft.AV1VideoExtension": "系统视频解码组件",
    "Microsoft.VP9VideoExtensions": "系统视频解码组件",
    "Microsoft.WebMediaExtensions": "系统媒体组件",
    "Microsoft.WebpImageExtension": "系统图片解码组件",
}


def _friendly_uwp(name: str) -> str:
    if name in UWP_FRIENDLY:
        return UWP_FRIENDLY[name]
    for key, val in UWP_FRIENDLY.items():
        if key in name or name in key:
            return val
    suffix = name.split(".")[-1]
    suffix = re.sub(r"(?:Desktop|App|_8wekyb3d8bbwe)$", "", suffix)
    suffix = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", suffix)
    return suffix.replace("_", " ") or name


# --------------------------------------------------------------- scan manager
def _safe_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("mbcs", "replace")
        except Exception:
            return value.decode("utf-8", "replace")
    return str(value).strip().strip("\x00")


_GUID_RE = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.IGNORECASE)
_CERT_LABEL_RE = re.compile(r"^(CN|O|L|S|C|E|OU|ST)\s*=", re.IGNORECASE)


def _uwp_publisher(package_name: str, publisher_dn: str, display_publisher: str) -> str:
    """A readable publisher for a Store package.

    Store packages are often signed with a certificate subject that only
    contains a GUID, so the manifest publisher name or the package's vendor
    prefix is used instead.
    """
    candidates: list[str] = []
    for raw in (display_publisher, publisher_dn):
        value = _safe_str(raw)
        if not value:
            continue
        if _CERT_LABEL_RE.match(value):
            chunks = [part.strip() for part in re.split(r",(?![^\"']*[\"])", value)]
            for chunk in chunks:
                if chunk.upper().startswith("CN=") or chunk.upper().startswith("O="):
                    candidates.append(chunk.split("=", 1)[1].strip(' "'))
                    break
        else:
            candidates.append(value)
    for candidate in candidates:
        if candidate and not _GUID_RE.fullmatch(candidate):
            return candidate[:120]
    prefix = _safe_str(package_name).split(".")[0].strip()
    if prefix and not _GUID_RE.fullmatch(prefix):
        return prefix[:120]
    return "Microsoft Store 发布商"


def _parse_date(value) -> str | None:
    s = _safe_str(value)
    if re.fullmatch(r"\d{8}", s):
        try:
            return datetime.strptime(s, "%Y%m%d").strftime("%Y-%m-%d")
        except ValueError:
            return None
    m = re.match(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", s)
    if m:
        return f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    return None


def _parse_kb(value) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n <= 0 or n > 100 * 1024 * 1024:  # ignore absurd registry values (>100 TB)
        return None
    return n * 1024


def _probably_update(name: str, values: dict) -> bool:
    low = name.casefold().strip()
    if re.match(r"^(update for|security update for|hotfix for|windows update|windows 更新|更新程序|安全更新)", low):
        return True
    if re.match(r"^kb\d{6,}", low):
        return True
    release = _safe_str(values.get("ReleaseType")).casefold()
    if any(x in release for x in ("update", "hotfix", "service pack")):
        return True
    if _safe_str(values.get("ParentKeyName")).casefold() == "operatingsystem":
        return True
    return False


_COMPONENT_PATTERNS = [
    re.compile(r"^Python \d+(?:\.\d+){1,3} (?:Core Interpreter|Standard Library|Executables|pip Bootstrap|Test Suite|Documentation|Development Libraries|Tcl/Tk Support|Utility Scripts|Add to Path)", re.I),
    re.compile(r"^Microsoft\.NET\.(?:Sdk|Workload)", re.I),
    re.compile(r"^Microsoft ASP\.NET Core .+ (?:Shared Framework|Targeting Pack) \(x64\)$", re.I),
    re.compile(r"^Office 16 Click-to-Run", re.I),
    re.compile(r"^VBA \(\d", re.I),
    re.compile(r"^Microsoft Visual C\+\+ .* (?:Minimum Runtime|Additional Runtime)", re.I),
    re.compile(r"^JetBrains ETW Host Service", re.I),
    re.compile(r"^vs_CoreEditorFonts", re.I),
]


def _is_component_name(name: str) -> bool:
    return any(p.match(name or "") for p in _COMPONENT_PATTERNS)


def _canonical_reg_path(root_label: str, subkey: str, view: int) -> str:
    sub = subkey
    if view & getattr(winreg, "KEY_WOW64_32KEY", 0x200):
        if "wow6432node" not in sub.casefold() and sub.upper().startswith("SOFTWARE\\"):
            sub = "SOFTWARE\\WOW6432Node\\" + sub[len("SOFTWARE\\"):]
    return root_label + "\\" + sub


def _extract_guid(value: str) -> str | None:
    m = re.search(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}", value or "")
    return m.group(0).upper() if m else None


def _read_values(key) -> dict:
    values: dict[str, object] = {}
    idx = 0
    while True:
        try:
            name, val, _kind = winreg.EnumValue(key, idx)
            values[name] = val
            idx += 1
        except OSError:
            break
    return values


def scan_registry_apps() -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    entries: list[dict] = []
    bases = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         getattr(winreg, "KEY_WOW64_64KEY", 0x100)),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         getattr(winreg, "KEY_WOW64_32KEY", 0x200)),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         getattr(winreg, "KEY_WOW64_64KEY", 0x100)),
        ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         getattr(winreg, "KEY_WOW64_32KEY", 0x200)),
    ]
    for root_label, root, base_sub, view in bases:
        try:
            base = winreg.OpenKey(root, base_sub, 0, winreg.KEY_READ | view)
        except OSError as exc:
            warnings.append(f"无法读取 {root_label} 卸载注册表：{exc}")
            continue
        with base:
            idx = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(base, idx)
                    idx += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(base, sub_name, 0, winreg.KEY_READ | view) as key:
                        vals = _read_values(key)
                except OSError:
                    continue
                name = _safe_str(vals.get("DisplayName"))
                if not name or name.startswith("@") or name.startswith("@{") and name.endswith("}"):
                    continue
                if _probably_update(name, vals):
                    continue
                if name.casefold().startswith(("softsweep", "净软")):
                    continue
                canonical = _canonical_reg_path(root_label, base_sub + "\\" + sub_name, view)
                uninstall_string = _safe_str(vals.get("UninstallString"))
                quiet = _safe_str(vals.get("QuietUninstallString"))
                location = _safe_str(vals.get("InstallLocation"))
                if location:
                    location = os.path.expandvars(location.strip().strip('"'))
                    if not os.path.isabs(location):
                        location = ""
                publisher = _safe_str(vals.get("Publisher"))
                if not location:
                    location = _resolve_install_location(vals, name, publisher)
                if not location and not uninstall_string:
                    # Registration-only leftovers are still shown, but only if
                    # they contain a publisher or version worth identifying.
                    if not (_safe_str(vals.get("Publisher")) or _safe_str(vals.get("DisplayVersion"))):
                        continue
                version = _safe_str(vals.get("DisplayVersion"))
                system_component = _safe_str(vals.get("SystemComponent")) in {"1", "true", "True"}
                no_remove = _safe_str(vals.get("NoRemove")) in {"1", "true", "True"}
                size_kb = _parse_kb(vals.get("EstimatedSize"))
                display_icon = _safe_str(vals.get("DisplayIcon"))
                install_date = _parse_date(vals.get("InstallDate"))
                guid = _extract_guid(sub_name) or _extract_guid(uninstall_string)
                entries.append({
                    "raw": {
                        "name": name, "publisher": publisher, "version": version,
                        "install_location": location, "uninstall_string": uninstall_string,
                        "quiet_uninstall_string": quiet, "display_icon": display_icon,
                        "uninstall_key": canonical, "install_date": install_date,
                        "estimated_bytes": size_kb,
                        "system_component": system_component, "no_remove": no_remove,
                        "guid": guid,
                    },
                    "sort": (0 if root_label == "HKLM" else 1, 0 if location else 1),
                })
    # Merge duplicate 32/64-bit or per-user registrations of the same product.
    merged: dict[tuple, dict] = {}
    for entry in entries:
        raw = entry["raw"]
        if raw["guid"]:
            sig = ("guid", raw["guid"])
        else:
            sig = (
                "name", norm_text(raw["name"]), raw["version"].casefold(),
                os.path.normcase(raw["install_location"]).casefold(), raw["publisher"].casefold(),
            )
        if sig not in merged:
            raw["uninstall_keys"] = [raw["uninstall_key"]]
            merged[sig] = raw
        else:
            kept = merged[sig]
            kept["uninstall_keys"] = list(dict.fromkeys(kept["uninstall_keys"] + [raw["uninstall_key"]]))
            for field in ("install_location", "uninstall_string", "quiet_uninstall_string",
                          "display_icon", "install_date", "publisher", "version"):
                if not kept.get(field) and raw.get(field):
                    kept[field] = raw[field]
            if not kept.get("estimated_bytes") and raw.get("estimated_bytes"):
                kept["estimated_bytes"] = raw["estimated_bytes"]
    apps = []
    for raw in merged.values():
        apps.append(_build_registry_app(raw))
    _validate_size_probes(apps)
    return apps, warnings


def _build_registry_app(raw: dict) -> dict:
    name = raw["name"]
    publisher = raw["publisher"]
    category = classify(name, publisher)
    location = raw["install_location"] or None
    uninstall = raw["uninstall_string"] or ""
    quiet = raw["quiet_uninstall_string"] or ""
    warnings: list[str] = []
    protected = category in PROTECTED_CATEGORIES
    protected_reason = {
        "system": "Windows 系统组件，移除可能影响系统稳定性和后续更新",
        "driver": "设备驱动程序，移除可能导致硬件无法正常工作",
        "runtime": "系统或第三方软件依赖的运行库/组件",
    }.get(category, "")
    if location and any(
        os.path.normcase(location).startswith(os.path.normcase(str(p)))
        for p in (WINDOWS_DIR,)
    ):
        category = "system"
        protected = True
        protected_reason = protected_reason or "安装于 Windows 系统目录"
    if location and _RUNTIME_DIR:
        loc_norm = os.path.normcase(os.path.abspath(location)).rstrip("\\")
        runtime_hit = (_RUNTIME_DIR == loc_norm or _RUNTIME_DIR.startswith(loc_norm + "\\")
                       or loc_norm.startswith(_RUNTIME_DIR + "\\"))
        if runtime_hit:
            protected = True
            protected_reason = "该目录包含 SoftSweep 正在使用的 Python 运行环境，删除会中断本工具"
    no_remove = bool(raw.get("no_remove"))
    is_component = bool(raw.get("system_component")) or _is_component_name(name)
    if is_component and not protected:
        protected = True
        protected_reason = "软件安装包的内部组件或系统支撑项，建议随所属软件一起卸载"
    if no_remove and not protected:
        warnings.append("安装信息标记为不可卸载；不能使用强制清理，建议使用软件自带卸载程序")
    if not uninstall:
        warnings.append("未提供标准卸载程序，只能清理已发现的关联文件")
    if raw.get("system_component") and not protected:
        warnings.append("系统组件注册项，请确认不再被其他软件使用")
    if "edge" in name.casefold() and "webview" not in name.casefold() and "update" not in name.casefold():
        warnings.append("Microsoft Edge 是系统浏览器，卸载可能影响系统内置网页功能")
    if not location and not uninstall:
        warnings.append("安装目录与卸载程序均未找到，可能是残留注册信息")
    if raw.get("guid") and uninstall.casefold().startswith("msiexec"):
        # MSI maintenance can remove the product. Keep the original command.
        pass
    exists = bool(location and os.path.isdir(location))
    if location and not exists:
        warnings.append("注册表中记录的安装目录当前不存在")
    aliases = app_aliases(name, publisher)
    probe_folder = "" if (protected or exists) else _inferred_program_folder(raw, aliases)
    category_info = CATEGORY_MAP.get(category, CATEGORY_MAP["other"])
    app_id = make_id("a", raw["uninstall_key"])
    source = "system" if protected else "thirdparty"
    size = {
        "bytes": raw.get("estimated_bytes"),
        "install_bytes": None,
        "data_bytes": None,
        "estimated": bool(raw.get("estimated_bytes")),
        "exact": False,
        "computing": False,
        "partial": False,
        "probe": False,
    }
    return {
        "id": app_id,
        "kind": "registry",
        "name": name,
        "version": raw["version"],
        "publisher": publisher,
        "install_date": raw["install_date"],
        "install_location": location,
        "install_location_display": display_env_path(location) if location else "",
        "on_system_drive": bool(location and system_drive_is(location)),
        "uninstall_string": uninstall,
        "quiet_uninstall_string": quiet,
        "display_icon": raw["display_icon"],
        "uninstall_key": raw["uninstall_key"],
        "uninstall_keys": raw.get("uninstall_keys", []),
        "package_full_name": "",
        "package_family_name": "",
        "category": category,
        "category_label": category_info["label"],
        "category_color": category_info["color"],
        "source": source,
        "source_label": SOURCE_LABELS[source],
        "protected": protected,
        "protected_reason": protected_reason,
        "is_component": is_component,
        "primary": not protected,
        "warnings": warnings,
        "can_uninstall": bool(uninstall) and not no_remove and not protected,
        "can_force": not protected and not no_remove,
        "uninstall_kind": "registry",
        "requires_admin": raw["uninstall_key"].startswith("HKLM") or (
            bool(location) and any(
                os.path.normcase(location).startswith(os.path.normcase(str(p)))
                for p in (PROGRAM_FILES, PROGRAM_FILES_X86, WINDOWS_DIR)
            )
        ),
        "size": size,
        "size_probe_path": probe_folder,
        "size_state": "protected" if protected else (
            "computing" if (exists or probe_folder)
            else ("estimated" if raw.get("estimated_bytes") else "unknown")
        ),
        "location_exists": exists,
        "aliases": sorted(aliases),
    }


def scan_uwp_apps() -> tuple[list[dict], list[str]]:
    warnings: list[str] = []
    script = """
$out = @()
Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
  $_.Status -eq 'Ok' -and -not $_.IsFramework -and -not $_.IsResourcePackage
} | ForEach-Object {
  $storeLogo = ''
  $square44 = ''
  $square150 = ''
  $pubDisplay = ''
  try {
    $manifest = Get-AppxPackageManifest -Package $_.PackageFullName -ErrorAction Stop
    if ($manifest -and $manifest.Package.Properties) {
      $storeLogo = [string]$manifest.Package.Properties.Logo
      $pubDisplay = [string]$manifest.Package.Properties.PublisherDisplayName
    }
    foreach ($application in @($manifest.Package.Applications.Application)) {
      if (-not $square44 -and $application.VisualElements.Square44x44Logo) {
        $square44 = [string]$application.VisualElements.Square44x44Logo
      }
      if (-not $square150 -and $application.VisualElements.Square150x150Logo) {
        $square150 = [string]$application.VisualElements.Square150x150Logo
      }
    }
  } catch { }
  $out += [PSCustomObject]@{
    Name = [string]$_.Name
    PackageFullName = [string]$_.PackageFullName
    PackageFamilyName = [string]$_.PackageFamilyName
    Version = [string]$_.Version
    Publisher = [string]$_.Publisher
    PublisherDisplayName = $pubDisplay
    InstallLocation = [string]$_.InstallLocation
    SignatureKind = [string]$_.SignatureKind
    NonRemovable = [bool]$(try { $_.NonRemovable } catch { $false })
    Square44Logo = $square44
    Square150Logo = $square150
    StoreLogo = $storeLogo
  }
}
$out | ConvertTo-Json -Compress -Depth 4
"""
    try:
        proc = run_powershell(script, timeout=70)
        text = decode_output(proc.stdout).strip()
        if not text:
            if proc.returncode != 0:
                warnings.append("读取 Microsoft Store 应用列表失败：" + decode_output(proc.stderr)[:300])
            return [], warnings
        data = json.loads(text)
        if isinstance(data, dict):
            data = [data]
    except Exception as exc:
        warnings.append(f"读取 Microsoft Store 应用列表失败：{exc}")
        return [], warnings

    apps: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = _safe_str(item.get("Name"))
        if not name:
            continue
        folded_name = name.casefold()
        hidden = any(folded_name.startswith(prefix.casefold()) for prefix in UWP_HIDE_PREFIXES)
        if hidden or folded_name == "aimgr" or re.fullmatch(
            r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", folded_name
        ):
            continue
        if not item.get("InstallLocation"):
            continue
        friendly = _friendly_uwp(name)
        publisher_dn = _safe_str(item.get("Publisher"))
        publisher = _uwp_publisher(
            name, publisher_dn, _safe_str(item.get("PublisherDisplayName"))
        )
        category = _category_for_uwp(name, friendly)
        protected_reason = UWP_PROTECTED.get(name, "")
        non_removable = bool(item.get("NonRemovable"))
        if non_removable and not protected_reason:
            protected_reason = "系统标记为不可移除此应用"
        protected = bool(protected_reason)
        if protected and category not in PROTECTED_CATEGORIES:
            pass
        warnings_list = []
        if item.get("SignatureKind", "").casefold() == "system" and not protected:
            warnings_list.append("系统签名应用，卸载后可能需要通过 Microsoft Store 重新安装")
        if name.startswith("Microsoft.") and not protected:
            warnings_list.append("Microsoft 内置应用，卸载后可在应用商店中重新获取")
        family = _safe_str(item.get("PackageFamilyName"))
        full = _safe_str(item.get("PackageFullName"))
        category_info = CATEGORY_MAP.get(category, CATEGORY_MAP["other"])
        install_location = _safe_str(item.get("InstallLocation"))
        package_data_path = str(LOCAL_APPDATA / "Packages" / family) if family else ""
        app = {
            "id": make_id("u", family or full),
            "kind": "uwp",
            "name": friendly,
            "version": _safe_str(item.get("Version")),
            "publisher": publisher,
            "install_date": None,
            "install_location": install_location,
            "install_location_display": install_location,
            "package_data_path": package_data_path,
            "on_system_drive": system_drive_is(install_location or "C:\\"),
            "uninstall_string": "",
            "quiet_uninstall_string": "",
            "display_icon": "",
            "uninstall_key": "",
            "uninstall_keys": [],
            "package_full_name": full,
            "package_family_name": family,
            "package_name": name,
            "uwp_logos": [
                logo for logo in (
                    _safe_str(item.get("Square44Logo")),
                    _safe_str(item.get("Square150Logo")),
                    _safe_str(item.get("StoreLogo")),
                ) if logo
            ],
            "category": category,
            "category_label": category_info["label"],
            "category_color": category_info["color"],
            "source": "store",
            "source_label": SOURCE_LABELS["store"],
            "protected": protected,
            "protected_reason": protected_reason,
            "is_component": False,
            "primary": not protected,
            "warnings": warnings_list,
            "can_uninstall": not protected,
            "can_force": not protected,
            "uninstall_kind": "uwp",
            "requires_admin": False,
            "size": {
                "bytes": None,
                "install_bytes": None,
                "data_bytes": None,
                "estimated": False,
                "exact": False,
                "computing": True,
                "partial": False,
                "probe": False,
            },
            "size_state": "computing",
            "location_exists": True,
            "aliases": sorted(app_aliases(friendly, publisher)),
        }
        apps.append(app)
    return apps, warnings


class ScanManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.apps: list[dict] = []
        self.status = "idle"
        self.phase = "等待扫描"
        self.error: str | None = None
        self.notices: list[str] = []
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.generation = 0
        self._scanning = False
        self._size_cache: dict[str, tuple[float, int, bool, str | None]] = {}

    def start(self):
        with self.lock:
            if self._scanning:
                return False
            self._scanning = True
            self.status = "scanning"
            self.phase = "正在读取已安装软件…"
            self.error = None
            self.notices = []
            self.started_at = time.time()
            self.finished_at = None
            self.generation += 1
            generation = self.generation
        threading.Thread(target=self._run_scan, args=(generation,), daemon=True, name="softsweep-scan").start()
        return True

    def _set_phase(self, text: str, generation: int):
        with self.lock:
            if generation == self.generation:
                self.phase = text

    def _run_scan(self, generation: int):
        try:
            self._set_phase("正在读取注册表卸载信息…", generation)
            registry_apps, registry_warnings = scan_registry_apps()
            self._set_phase("正在读取 Microsoft Store 应用…", generation)
            uwp_apps, uwp_warnings = scan_uwp_apps()
            notices = registry_warnings + uwp_warnings
            all_apps: dict[str, dict] = {}
            for app in registry_apps + uwp_apps:
                all_apps[app["id"]] = app
            apps = list(all_apps.values())
            apps.sort(key=lambda a: (a["protected"], a["name"].casefold()))
            with self.lock:
                if generation != self.generation:
                    return
                self.apps = apps
                self.notices = notices
                self.status = "ready"
                self.phase = "扫描完成"
                self.finished_at = time.time()
                self._scanning = False
            self._start_size_workers(generation, apps)
            try:
                icon_store.warm_async(apps)
            except Exception:
                traceback.print_exc()
        except Exception as exc:
            with self.lock:
                if generation == self.generation:
                    self.status = "error"
                    self.error = f"{exc}"
                    self.phase = "扫描失败"
                    self._scanning = False
                    self.finished_at = time.time()
            traceback.print_exc()

    def _cached_measure(self, path: str, max_seconds: float) -> dict:
        key = os.path.normcase(os.path.abspath(path))
        cached = self._size_cache.get(key)
        if cached and time.monotonic() - cached[0] < 600:
            return {"bytes": cached[1], "partial": cached[2], "error": cached[3]}
        result = measure_path(path, max_seconds=max_seconds)
        entry = (
            time.monotonic(),
            int(result.get("bytes") or 0),
            bool(result.get("partial")),
            result.get("error"),
        )
        self._size_cache[key] = entry
        return {"bytes": entry[1], "partial": entry[2], "error": entry[3]}

    def _measure_app_size(self, app: dict) -> dict:
        """Total space used by an app: install folder plus Store app data."""
        is_uwp = app.get("kind") == "uwp"
        recorded = app.get("install_location") or ""
        install = recorded if (recorded and os.path.isdir(recorded)) else ""
        used_probe = False
        if not install:
            install = _safe_str(app.get("size_probe_path"))
            used_probe = bool(install and os.path.isdir(install))
            if not used_probe:
                install = ""
        install_res = self._cached_measure(install, 12.0 if is_uwp else 14.0) if install else None
        install_bytes = int(install_res["bytes"]) if install_res else 0

        data_bytes = 0
        data_res = None
        data_path = _safe_str(app.get("package_data_path")) if is_uwp else ""
        if data_path and os.path.isdir(data_path) and install:
            install_norm = os.path.normcase(os.path.abspath(install)).rstrip(os.sep)
            data_norm = os.path.normcase(os.path.abspath(data_path)).rstrip(os.sep)
            nested = (
                data_norm == install_norm
                or data_norm.startswith(install_norm + os.sep)
                or install_norm.startswith(data_norm + os.sep)
            )
            if not nested:
                data_res = self._cached_measure(data_path, 10.0)
                data_bytes = int(data_res["bytes"])

        error_text = _safe_str((install_res or {}).get("error")).lower()
        denied = bool(install_res) and install_bytes == 0 and (
            "winerror 5" in error_text
            or "permission" in error_text
            or "denied" in error_text
            or "拒绝" in error_text
        )
        missing = bool(install_res) and (install_res.get("error") == "not_found" or not os.path.isdir(install))
        partial = bool((install_res or {}).get("partial")) or bool((data_res or {}).get("partial"))
        total = None
        if install_res and not denied and not missing:
            total = install_bytes + data_bytes
        return {
            "install_bytes": install_bytes if install_res else None,
            "data_bytes": data_bytes if data_res else None,
            "total": total,
            "partial": partial,
            "denied": denied or missing,
            "probe": used_probe,
        }

    def _start_size_workers(self, generation: int, apps: list[dict]):
        def measurable(app: dict) -> bool:
            if app.get("protected") and app.get("kind") != "uwp":
                return False
            for path in (app.get("install_location") or "", _safe_str(app.get("size_probe_path"))):
                if path and os.path.isdir(path):
                    return True
            return False

        candidates = [
            app for app in apps
            if app.get("kind") in ("registry", "uwp") and measurable(app)
        ]
        if not candidates:
            return
        # Manageable software first, then protected components; Store packages are
        # measured by install folder plus their per-user data folder.
        candidates.sort(key=lambda app: (bool(app.get("protected")), app["kind"] != "registry"))
        with self.lock:
            for app in candidates:
                app["size"]["computing"] = True
                app["size_state"] = "computing"

        def work(app: dict):
            measurement = self._measure_app_size(app)
            with self.lock:
                if generation != self.generation:
                    return
                for current in self.apps:
                    if current["id"] != app["id"]:
                        continue
                    size = current["size"]
                    size["install_bytes"] = measurement["install_bytes"]
                    size["data_bytes"] = measurement["data_bytes"]
                    size["partial"] = measurement["partial"]
                    size["probe"] = measurement["probe"]
                    size["computing"] = False
                    total = measurement["total"]
                    if measurement["denied"]:
                        size["bytes"] = None
                        size["exact"] = False
                        current["size_state"] = "denied"
                    elif total is not None:
                        size["bytes"] = total
                        size["exact"] = not measurement["partial"]
                        size["estimated"] = False
                        current["size_state"] = "too_many_files" if measurement["partial"] else "exact"
                    elif not size.get("estimated"):
                        size["bytes"] = None
                        size["exact"] = False
                        current["size_state"] = "unknown"
                    break

        def guarded(app):
            try:
                work(app)
            except Exception:
                with self.lock:
                    for current in self.apps:
                        if current["id"] == app["id"]:
                            current["size"]["computing"] = False
                            current["size_state"] = (
                                "estimated" if current["size"].get("estimated") else "unknown"
                            )
                            break

        def dispatcher():
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=6, thread_name_prefix="softsweep-size"
            ) as pool:
                list(pool.map(guarded, candidates))

        threading.Thread(target=dispatcher, daemon=True, name="softsweep-size-pool").start()

    def snapshot(self) -> dict:
        with self.lock:
            apps = []
            pending = 0
            for app in self.apps:
                item = dict(app)
                item["size"] = dict(app["size"])
                item["warnings"] = list(app["warnings"])
                item["icon_version"] = icon_store.version_for(app["id"])
                if item["size"].get("computing"):
                    pending += 1
                apps.append(item)
            return {
                "status": self.status,
                "phase": self.phase,
                "error": self.error,
                "notices": list(self.notices),
                "apps": apps,
                "pending_sizes": pending,
                "is_admin": is_admin(),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "categories": CATEGORY_DEFS,
            }

    def get_app(self, app_id: str) -> dict | None:
        with self.lock:
            for app in self.apps:
                if app["id"] == app_id:
                    item = dict(app)
                    item["size"] = dict(app["size"])
                    item["warnings"] = list(app["warnings"])
                    item["icon_version"] = icon_store.version_for(app["id"])
                    return item
        return None

    def all_apps(self) -> list[dict]:
        with self.lock:
            return [dict(app) for app in self.apps]


SCANNER = ScanManager()
