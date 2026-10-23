"""Uninstall / deep-clean job engine.

Safety model:
  * only one job may run at a time;
  * protected apps are rejected;
  * the official uninstaller is launched first (unless force mode);
  * nothing is deleted until the user confirms the discovered leftovers;
  * files go to the Recycle Bin unless an exact app-name confirmation is supplied;
  * every registry deletion is exported to a .reg backup first.
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import threading
import time
import traceback
import unicodedata
import uuid
import winreg
from datetime import datetime
from pathlib import Path

from . import icons as icon_store
from . import winutil as wu
from .leftovers import discover_leftovers
from .scanner import SCANNER, scan_registry_apps, scan_uwp_apps

ACTIVE_STATUSES = {
    "starting", "uninstalling", "waiting", "scanning", "awaiting_cleanup", "cleaning",
}
FINAL_STATUSES = {"completed", "failed", "cancelled"}
_JOB_ID_RE = re.compile(r"^j[0-9a-f]{16}$")
STATUS_LABELS = {
    "starting": "正在准备",
    "uninstalling": "等待官方卸载完成",
    "waiting": "等待卸载程序",
    "scanning": "正在扫描残留",
    "awaiting_cleanup": "请确认要清理的文件",
    "cleaning": "正在清理",
    "completed": "已完成",
    "failed": "失败",
    "cancelled": "已取消",
}


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


_NAME_NOISE_RE = re.compile(r"[\u00ad\u200b-\u200f\u2060\ufeff]")
_NAME_BRACKET_SPACE_RE = re.compile(r"\s*([()\[\]])\s*")


def normalize_software_name(value: object) -> str:
    """Canonical form used to confirm a destructive cleanup.

    The displayed name may contain full-width punctuation, a non-breaking
    space or an invisible zero-width character.  Users cannot reasonably
    reproduce those by hand, so compare a normalised form instead of raw
    bytes.  Case is intentionally preserved.
    """
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = _NAME_NOISE_RE.sub("", text)
    text = _NAME_BRACKET_SPACE_RE.sub(r"\1", text)
    return " ".join(text.split())


def _key_exists(path: str) -> bool:
    try:
        if path.upper().startswith("HKCU\\"):
            return _open_key(winreg.HKEY_CURRENT_USER, path[5:])
        if path.upper().startswith("HKLM\\"):
            return _open_key(winreg.HKEY_LOCAL_MACHINE, path[5:])
    except OSError:
        return False
    return False


def _open_key(root, sub: str) -> bool:
    try:
        with winreg.OpenKey(root, sub, 0, winreg.KEY_READ):
            return True
    except OSError:
        return False


def _normalize_uninstall_command(command: str) -> str:
    """Turn the common MsiExec /I maintenance command into a real uninstall (/X)."""
    cmd = os.path.expandvars((command or "").strip())
    if not cmd:
        return ""
    if re.match(r'^"?msiexec(?:\.exe)?"?(\s|$)', cmd, re.IGNORECASE):
        cmd = re.sub(r'(?<!\S)/i(?=\s|\{|\")', '/X', cmd, count=1, flags=re.IGNORECASE)
    exe = wu.command_executable(cmd)
    if exe and os.path.isabs(exe) and os.path.exists(exe) and not cmd.startswith('"'):
        rest = cmd[len(exe):].lstrip()
        cmd = f'"{exe}"' + (f" {rest}" if rest else "")
    return cmd


def _launch_process(command: str, cwd: str | None, require_admin: bool) -> dict:
    """Launch an uninstaller. Returns {launched, pid, elevated, error}."""
    if not wu.is_admin() and require_admin:
        code = wu.runas_elevate("cmd.exe", f'/c "{command}"', cwd)
        if code > 32:
            return {"launched": True, "pid": None, "elevated": True, "error": None}
        return {"launched": False, "pid": None, "elevated": False,
                "error": "管理员权限请求被取消或失败"}
    try:
        proc = subprocess.Popen(
            command,
            cwd=cwd if cwd and os.path.isdir(cwd) else None,
            shell=False,
        )
        return {"launched": True, "pid": proc.pid, "elevated": False,
                "process": proc, "error": None}
    except OSError as exc:
        if getattr(exc, "winerror", None) == 740:
            code = wu.runas_elevate("cmd.exe", f'/c "{command}"', cwd)
            if code > 32:
                return {"launched": True, "pid": None, "elevated": True, "error": None}
            return {"launched": False, "pid": None, "elevated": False,
                    "error": "需要管理员权限，但提权被取消"}
        return {"launched": False, "pid": None, "elevated": False, "error": str(exc)}


def _fresh_scan() -> tuple[list[dict], list[str]]:
    registry_apps, w1 = scan_registry_apps()
    uwp_apps, w2 = scan_uwp_apps()
    return registry_apps + uwp_apps, w1 + w2


def _same_app(app: dict, candidate: dict) -> bool:
    if app.get("kind") != candidate.get("kind"):
        return False
    if app.get("kind") == "uwp":
        return bool(
            app.get("package_family_name") and
            app.get("package_family_name") == candidate.get("package_family_name")
        )
    keys = set(app.get("uninstall_keys") or [app.get("uninstall_key")])
    cand = set(candidate.get("uninstall_keys") or [candidate.get("uninstall_key")])
    return bool(keys & cand)


class Job:
    def __init__(self, app: dict, mode: str, jobs: "JobsManager"):
        self.id = "j" + uuid.uuid4().hex[:16]
        self.app = copy.deepcopy(app)
        self.confirm_name = str(self.app.get("name") or "")
        # A registration whose install folder and uninstaller are both absent
        # cannot use the official uninstall flow. Start directly with the
        # audited leftover scan instead of failing on a dead command.
        self.fallback_used = bool(mode == "uninstall" and app.get("stale_registration"))
        if self.fallback_used:
            mode = "force"
        self.mode = mode
        self.fallback_available = False
        self.stale_registration = bool(app.get("stale_registration"))
        self.jobs = jobs
        self.lock = threading.RLock()
        self.cancel_event = threading.Event()
        self.recheck_event = threading.Event()
        self.status = "starting"
        self.phase = "准备卸载"
        self.message = ""
        self.created_at = time.time()
        self.updated_at = self.created_at
        self.finished_at: float | None = None
        self.leftover: dict | None = None
        self.still_installed: bool | None = None
        self.cleanup_result: dict | None = None
        self.installed_check: dict | None = None
        self.logs: list[dict] = []
        self.process: subprocess.Popen | None = None
        self.pid: int | None = None
        self.elevated = False
        self.launched = False
        self.report_path: str | None = None
        self._log("任务已创建", "info")

    # ---------------------------------------------------------------- helpers
    def _log(self, message: str, level: str = "info"):
        with self.lock:
            self.logs.append({"time": _now_text(), "level": level, "message": message})
            if len(self.logs) > 300:
                del self.logs[:50]
            self.updated_at = time.time()

    def _set(self, status: str | None = None, phase: str | None = None, message: str | None = None):
        with self.lock:
            if status:
                self.status = status
            if phase is not None:
                self.phase = phase
            if message is not None:
                self.message = message
            self.updated_at = time.time()

    @property
    def active(self) -> bool:
        with self.lock:
            return self.status not in FINAL_STATUSES

    def snapshot(self, include_leftover: bool = True) -> dict:
        with self.lock:
            app_snapshot = copy.deepcopy(self.app)
            app_snapshot["icon_version"] = icon_store.version_for(app_snapshot.get("id") or "")
            data = {
                "id": self.id,
                "status": self.status,
                "status_label": STATUS_LABELS.get(self.status, self.status),
                "phase": self.phase,
                "message": self.message,
                "mode": self.mode,
                "app": app_snapshot,
                "app_id": self.app.get("id"),
                "app_name": self.app.get("name") or self.confirm_name,
                "confirm_name": self.confirm_name or self.app.get("name") or "",
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "finished_at": self.finished_at,
                "active": self.status not in FINAL_STATUSES,
                "is_admin": wu.is_admin(),
                "launched": self.launched,
                "elevated": self.elevated,
                "pid": self.pid,
                "can_fallback": bool(
                    self.fallback_available and self.status == "failed"
                ),
                "fallback_used": bool(self.fallback_used),
                "stale_registration": bool(self.stale_registration),
                "still_installed": self.still_installed,
                "installed_check": self.installed_check,
                "cleanup": self.cleanup_result,
                "report_path": self.report_path,
                "logs": list(self.logs),
            }
            if include_leftover:
                data["leftover"] = copy.deepcopy(self.leftover)
            return data

    def _persist(self):
        """Save a recovery snapshot. A failed write must never break the job."""
        try:
            self.jobs.save_job_state(self.snapshot())
        except Exception:
            pass

    @classmethod
    def from_snapshot(cls, data: dict, jobs: "JobsManager") -> "Job | None":
        """Rebuild a job from a persisted snapshot (used after a restart)."""
        if not isinstance(data, dict):
            return None
        app = data.get("app")
        job_id = data.get("id")
        if not isinstance(app, dict):
            return None
        saved_name = data.get("confirm_name") or data.get("app_name") or app.get("name") or ""
        if not str(saved_name).strip():
            return None
        if not isinstance(job_id, str) or not _JOB_ID_RE.match(job_id):
            return None
        job = cls.__new__(cls)
        job.id = job_id
        job.app = copy.deepcopy(app)
        # Older snapshots only stored app_name at the top level. Keep that as
        # the authoritative confirmation target when app.name is missing.
        job.confirm_name = str(saved_name)
        if not str(job.app.get("name") or "").strip():
            job.app["name"] = job.confirm_name
        mode = data.get("mode")
        job.mode = mode if mode in {"uninstall", "force"} else "force"
        job.jobs = jobs
        job.lock = threading.RLock()
        job.cancel_event = threading.Event()
        job.recheck_event = threading.Event()
        status = data.get("status")
        job.status = status if status in STATUS_LABELS else "failed"
        job.phase = str(data.get("phase") or "")
        job.message = str(data.get("message") or "")
        try:
            job.created_at = float(data.get("created_at") or time.time())
        except (TypeError, ValueError):
            job.created_at = time.time()
        try:
            job.updated_at = float(data.get("updated_at") or job.created_at)
        except (TypeError, ValueError):
            job.updated_at = job.created_at
        finished = data.get("finished_at")
        job.finished_at = float(finished) if isinstance(finished, (int, float)) else None
        leftover = data.get("leftover")
        job.leftover = copy.deepcopy(leftover) if isinstance(leftover, dict) else None
        job.still_installed = data.get("still_installed") if isinstance(
            data.get("still_installed"), bool) else None
        cleanup_result = data.get("cleanup")
        job.cleanup_result = copy.deepcopy(cleanup_result) if isinstance(cleanup_result, dict) else None
        installed_check = data.get("installed_check")
        job.installed_check = copy.deepcopy(installed_check) if isinstance(installed_check, dict) else None
        logs = []
        for entry in data.get("logs") or []:
            if not isinstance(entry, dict):
                continue
            logs.append({
                "time": str(entry.get("time") or ""),
                "level": str(entry.get("level") or "info"),
                "message": str(entry.get("message") or ""),
            })
        job.logs = logs[-300:]
        job.process = None
        job.pid = data.get("pid") if isinstance(data.get("pid"), int) else None
        job.elevated = bool(data.get("elevated"))
        job.launched = bool(data.get("launched"))
        job.fallback_used = bool(data.get("fallback_used"))
        job.stale_registration = bool(data.get("stale_registration"))
        # Snapshots written by older builds did not carry fallback_available.
        # A failed uninstall that never launched can still be recovered by
        # scanning leftovers, so expose that action for existing jobs too.
        job.fallback_available = bool(data.get("fallback_available")) or bool(
            job.status == "failed"
            and job.mode == "uninstall"
            and not job.launched
            and not job.leftover
            and job.app.get("kind") == "registry"
            and not job.app.get("protected")
        )
        report_path = data.get("report_path")
        job.report_path = report_path if isinstance(report_path, str) and report_path else None
        return job

    # ------------------------------------------------------------------- flow
    def start(self):
        threading.Thread(target=self._run, daemon=True, name=f"job-{self.id}").start()

    def _run(self):
        try:
            if self.cancel_event.is_set():
                self._cancelled()
                return
            if self.mode == "force":
                if self.stale_registration:
                    self._set(
                        "scanning", "正在扫描失效登记与残留",
                        "安装目录与卸载程序均不存在；只扫描，确认后才会清理",
                    )
                    self._log("安装目录与卸载程序均不存在：跳过官方卸载，直接清理失效登记与残留", "warn")
                elif self.fallback_used:
                    self._set(
                        "scanning", "官方卸载程序不可用，正在扫描残留",
                        "将列出可清理的残留；只有你确认后才会删除",
                    )
                    self._log("官方卸载程序不可用：跳过官方卸载，改为扫描残留", "warn")
                else:
                    self._set("scanning", "正在扫描软件残留", "强制清理模式：不会启动官方卸载程序")
                    self._log("强制清理模式：跳过官方卸载程序", "warn")
                self._scan_after_uninstall(force=True)
            else:
                if self._uninstaller_missing():
                    self.mode = "force"
                    self.fallback_used = True
                    self.stale_registration = self._registration_is_stale()
                    command = _normalize_uninstall_command(self.app.get("uninstall_string") or "")
                    self._log("未找到官方卸载程序：" + (command or "（未登记卸载命令）"), "warn")
                    self._log("已自动改为仅清理残留；不会自动删除任何文件", "warn")
                    self._set(
                        "scanning", "官方卸载程序不可用，正在扫描残留",
                        "将列出可清理的残留与失效登记；只有你确认后才会删除",
                    )
                    self._scan_after_uninstall(force=True)
                elif not self._launch_uninstaller():
                    self._fail("无法启动卸载程序", fallback=True)
                    return
                else:
                    self._wait_for_uninstall()
                    if self.cancel_event.is_set():
                        self._cancelled()
                        return
                    self._scan_after_uninstall(force=False)
            if self.cancel_event.is_set():
                self._cancelled()
                return
            self.jobs.refresh_main_scan()
        except Exception as exc:
            traceback.print_exc()
            self._log(f"任务异常：{exc}", "error")
            self._fail(f"任务异常：{exc}")

    def _install_folder_exists(self) -> bool:
        location = self.app.get("install_location") or ""
        return bool(location and os.path.isdir(location))

    def _uninstaller_missing(self) -> bool:
        if self.app.get("kind") == "uwp":
            return False
        command = _normalize_uninstall_command(self.app.get("uninstall_string") or "")
        if not command:
            return True
        exe = wu.command_executable(command)
        if not exe:
            return True
        if not os.path.isabs(exe):
            # A bare command such as msiexec is resolved through PATH.
            return False
        return not os.path.isfile(exe)

    def _registration_is_stale(self) -> bool:
        """Both the install folder and the uninstaller are gone."""
        if self.app.get("kind") != "registry" or self.app.get("protected"):
            return False
        return not self._install_folder_exists() and self._uninstaller_missing()

    def _apply_still_installed_defaults(self, leftover: dict) -> None:
        """Adjust defaults when the registry entry still exists after scanning.

        A live install is never preselected. A stale registration (no folder,
        no uninstaller) may be removed from the installed list, but only the
        registration key is preselected; user data still needs a manual look.
        """
        if not self.still_installed:
            return
        if self.stale_registration:
            keys = {
                str(key).casefold()
                for key in (self.app.get("uninstall_keys") or [self.app.get("uninstall_key")])
                if key
            }
            # Removing the dead registration is enough to stop listing the app.
            # Never preselect user data or shortcuts: those may still be wanted.
            for item in leftover.get("items", []):
                item["default_selected"] = False
            for item in leftover.get("items", []):
                if (item.get("kind") == "registry"
                        and str(item.get("path") or "").casefold() in keys):
                    item["default_selected"] = True
                    item["risk"] = "caution"
                    item["note"] = (
                        "失效的卸载登记：安装目录和卸载程序都不存在；"
                        "删除前会自动导出 .reg 备份"
                    )
            leftover["selected_bytes"] = 0
            leftover.setdefault("notice", []).append(
                "安装目录与卸载程序均不存在，这是一条失效的卸载登记；"
                "卸载注册项已默认勾选，用户数据和快捷方式请自行确认"
            )
            return
        for item in leftover.get("items", []):
            item["default_selected"] = False
            if item.get("section") == "install":
                item["risk"] = "high"
                item["note"] = (
                    "仅清理残留模式下默认不勾选；请确认该目录已不再需要"
                    if self.mode == "force"
                    else "软件似乎仍处于已安装状态，默认不勾选；请先确认卸载已完成"
                )
        leftover["selected_bytes"] = 0
        leftover.setdefault("notice", []).append(
            "“仅清理残留”模式不会移除卸载注册项，软件仍会出现在已安装列表中；"
            "为避免误删，所有项目默认未勾选"
            if self.mode == "force"
            else "检测到软件仍在已安装列表中：已默认取消所有勾选，避免破坏正在使用的软件"
        )

    def _launch_uninstaller(self) -> bool:
        app = self.app
        self._set("starting", "正在启动官方卸载程序")
        command = ""
        if app.get("kind") == "uwp":
            full = app.get("package_full_name") or ""
            if not full:
                self._log("缺少商店应用包信息", "error")
                return False
            self._log("正在调用 Windows 移除商店应用…")
            try:
                script = (
                    f"$p = Get-AppxPackage -PackageTypeFilter Main,Bundle | "
                    f"Where-Object {{ $_.PackageFullName -eq {wu.ps_quote(full)} }}; "
                    f"if (-not $p) {{ exit 0 }}; "
                    f"$p | Remove-AppxPackage -ErrorAction Stop"
                )
                proc = wu.run_powershell(script, timeout=300, no_window=True)
                if proc.returncode != 0:
                    err = wu.decode_output(proc.stderr).strip()
                    self._log(f"商店应用移除失败：{err[:400]}", "error")
                    return False
                self.launched = True
                self._log("商店应用移除命令已执行")
                self._set("waiting", "正在确认商店应用已移除")
                time.sleep(1.5)
                return True
            except subprocess.TimeoutExpired:
                self._log("商店应用移除超时", "error")
                return False
            except Exception as exc:
                self._log(f"商店应用移除失败：{exc}", "error")
                return False

        command = _normalize_uninstall_command(app.get("uninstall_string") or "")
        if not command:
            self._log("该软件没有可用的卸载命令", "error")
            return False
        self._log("卸载命令：" + command)
        result = _launch_process(command, app.get("install_location"), bool(app.get("requires_admin")))
        if not result.get("launched"):
            self._log("启动卸载程序失败：" + str(result.get("error")), "error")
            return False
        self.launched = True
        self.elevated = bool(result.get("elevated"))
        self.pid = result.get("pid")
        self.process = result.get("process")
        self._set("uninstalling", "请在卸载窗口中完成操作",
                  "卸载程序已启动，完成后会自动继续扫描残留" if not self.elevated
                  else "请在系统弹窗中允许管理员权限，并完成卸载")
        self._log("卸载程序已启动" + ("（已请求管理员权限）" if self.elevated else ""))
        return True

    def _wait_for_uninstall(self):
        app = self.app
        if app.get("kind") == "uwp":
            # Remove-AppxPackage is synchronous; give Windows a moment to commit.
            self._sleep(1.0)
            return
        keys = [k for k in (app.get("uninstall_keys") or [app.get("uninstall_key")]) if k]
        deadline = time.monotonic() + 20 * 60
        exited_at: float | None = None
        warned = False
        while time.monotonic() < deadline:
            if self.cancel_event.is_set() or self.recheck_event.is_set():
                return
            if keys and not any(_key_exists(k) for k in keys):
                self._log("卸载注册项已消失，官方卸载完成")
                return
            if self.process is not None:
                code = self.process.poll()
                if code is not None:
                    if exited_at is None:
                        exited_at = time.monotonic()
                        self._log(f"卸载程序已退出（代码 {code}），正在确认结果…")
                    if time.monotonic() - exited_at > 8:
                        return
            elif exited_at is None:
                exited_at = time.monotonic()
            if not warned and time.monotonic() - self.created_at > 180:
                self._set(message="卸载程序仍在运行；若已完成，请点击「重新检查」")
                warned = True
            self._sleep(1.3)
        self._log("等待卸载超时，转为手动检查", "warn")

    def _sleep(self, seconds: float):
        self.cancel_event.wait(seconds)

    def _scan_after_uninstall(self, *, force: bool):
        self._set("scanning", "正在重新扫描软件与关联文件")
        self._log("正在重新扫描已安装软件…")
        fresh, notices = _fresh_scan()
        still = None
        for candidate in fresh:
            if _same_app(self.app, candidate):
                still = candidate
                break
        self.still_installed = bool(still)
        self.stale_registration = bool(still) and self._registration_is_stale()
        self.installed_check = {
            "checked_at": _now_text(),
            "still_installed": bool(still),
            "stale_registration": self.stale_registration,
            "match": (still or {}).get("name", ""),
            "notice": notices[:3],
        }
        if self.stale_registration:
            self._log("安装目录与卸载程序均不存在：这是失效的安装登记", "warn")
            self._set(message="未找到安装文件；可勾选卸载注册项移除这条失效登记")
        elif still:
            self._log(f"软件仍在已安装列表中：{still.get('name')}", "warn")
            if not force and not self.recheck_event.is_set():
                self._set(message="官方卸载可能未完成；仍可手动选择残留文件，但请谨慎")
        else:
            self._log("软件已从已安装列表中移除")
        self._set(phase="正在查找残留文件、快捷方式和注册表项")
        try:
            leftover = discover_leftovers(self.app, fresh)
        except Exception as exc:
            traceback.print_exc()
            self._log(f"扫描关联文件失败：{exc}", "error")
            leftover = {
                "app_id": self.app.get("id"), "app_name": self.app.get("name"),
                "items": [], "sections": [], "selected_bytes": 0, "all_bytes": 0,
                "notice": [f"扫描关联文件失败：{exc}"], "scanned_at": time.time(),
                "duration": 0, "is_admin": wu.is_admin(),
            }
        self._apply_still_installed_defaults(leftover)
        self.leftover = leftover
        self._set("awaiting_cleanup", "请确认要清理的残留文件",
                  "已扫描完成，确认后才会删除任何文件" if leftover.get("items")
                  else "没有发现可安全清理的残留")
        self._log(f"残留扫描完成：{len(leftover.get('items', []))} 项")
        self._persist()
        if not leftover.get("items"):
            self._finish()

    def recheck(self):
        if self.status in {"uninstalling", "waiting"}:
            self.recheck_event.set()
            self._log("用户请求重新检查卸载结果")
            return True
        if self.status == "awaiting_cleanup":
            threading.Thread(target=self._refresh_leftovers, daemon=True).start()
            return True
        return False

    def _refresh_leftovers(self):
        try:
            if self.cancel_event.is_set():
                self._cancelled()
                return
            self._set("scanning", "正在重新扫描残留")
            fresh, _ = _fresh_scan()
            self.still_installed = any(_same_app(self.app, c) for c in fresh)
            self.stale_registration = bool(self.still_installed) and self._registration_is_stale()
            leftover = discover_leftovers(self.app, fresh)
            self._apply_still_installed_defaults(leftover)
            self.leftover = leftover
            if self.cancel_event.is_set():
                self._cancelled()
                return
            self._set("awaiting_cleanup", "请确认要清理的残留文件", "残留列表已刷新")
            self._log(f"残留列表已刷新：{len(leftover.get('items', []))} 项")
            self._persist()
            if not leftover.get("items"):
                self._finish()
        except Exception as exc:
            self._log(f"刷新残留失败：{exc}", "error")

    def cleanup(self, item_ids: list[str], *, permanent: bool = False, confirm_name: str = "") -> dict:
        with self.lock:
            if self.status != "awaiting_cleanup":
                return {"ok": False, "error": "当前任务不在可清理阶段"}
            if not self.leftover:
                return {"ok": False, "error": "没有残留清单"}
        if permanent:
            provided = normalize_software_name(confirm_name)
            expected = {
                normalize_software_name(self.app.get("name")),
                normalize_software_name(self.confirm_name),
            } - {""}
            if not provided or provided not in expected:
                return {"ok": False, "error": "永久删除需要输入完整软件名称"}
        wanted = set(item_ids or [])
        all_items = {i["id"]: i for i in (self.leftover.get("items") or [])}
        chosen = [all_items[i] for i in item_ids if i in all_items]
        if not chosen:
            return {"ok": False, "error": "请至少选择一项"}
        with self.lock:
            self.status = "cleaning"
            self.phase = "正在清理所选文件"
            self.updated_at = time.time()
        self._log(f"开始清理 {len(chosen)} 项" + ("（永久删除）" if permanent else "（移入回收站）"),
                  "warn" if permanent else "info")
        self._persist()
        backup_dir = wu.BACKUP_DIR / self.id
        backup_dir.mkdir(parents=True, exist_ok=True)
        uninstall_keys = {
            str(key).casefold()
            for key in (self.app.get("uninstall_keys") or [self.app.get("uninstall_key")])
            if key
        }
        removed_registration = False
        results = []
        removed = 0
        failed = 0
        for idx, item in enumerate(chosen, 1):
            if self.cancel_event.is_set():
                break
            kind = item.get("kind")
            path = item.get("path") or ""
            label = item.get("label") or kind
            result: dict
            try:
                if kind == "dir":
                    if not wu.is_safe_dir_path(path, trusted=True):
                        result = {"ok": False, "error": "安全策略拒绝删除该目录"}
                    else:
                        result = wu.delete_path(path, permanent=permanent)
                elif kind == "shortcut":
                    if not wu.is_safe_shortcut_path(path):
                        result = {"ok": False, "error": "安全策略拒绝删除该快捷方式"}
                    else:
                        result = wu.delete_path(path, permanent=permanent)
                elif kind == "registry":
                    if not wu.is_safe_registry_key(path):
                        result = {"ok": False, "error": "安全策略拒绝删除该注册表项"}
                    else:
                        backup = backup_dir / f"{idx:02d}_registry.reg"
                        result = wu.delete_registry_key(path, str(backup))
                elif kind == "registry_value":
                    value_name = item.get("value_name") or ""
                    if not wu.is_safe_run_value(path, value_name):
                        result = {"ok": False, "error": "安全策略拒绝删除该启动项"}
                    else:
                        backup = backup_dir / f"{idx:02d}_run.reg"
                        result = wu.delete_registry_value(path, value_name, str(backup))
                else:
                    result = {"ok": False, "error": "未知的项目类型"}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}
            ok = bool(result.get("ok"))
            if ok:
                size = item.get("bytes") or 0
                removed += size
                if kind == "registry" and path.casefold() in uninstall_keys:
                    removed_registration = True
            else:
                failed += 1
            results.append({
                "id": item["id"], "label": label, "kind": kind,
                "path": item.get("display_path") or path,
                "ok": ok, "missing": bool(result.get("missing")),
                "error": result.get("error") or "",
                "backup": result.get("backup") or "",
                "bytes": item.get("bytes"),
            })
            self._log(
                ("已清理" if ok else "清理失败") + f"：{item.get('display_path') or path}"
                + ("" if ok else f"（{result.get('error')}）"),
                "info" if ok else "error",
            )
        if removed_registration:
            self.still_installed = False
            self.stale_registration = False
        self.cleanup_result = {
            "items": results,
            "removed_bytes": removed,
            "failed": failed,
            "total": len(results),
            "permanent": permanent,
            "registration_removed": removed_registration,
            "backup_dir": str(backup_dir) if any(r.get("backup") for r in results) else "",
        }
        self._finish()
        self.jobs.refresh_main_scan()
        return {"ok": True, "cleanup": self.cleanup_result}

    def cancel(self) -> bool:
        if not self.active:
            return False
        self.cancel_event.set()
        self._log("用户取消了任务", "warn")
        with self.lock:
            status = self.status
        # These states have no worker that would observe the event and finish the job.
        if status in {"starting", "uninstalling", "waiting", "awaiting_cleanup"}:
            self._cancelled()
        return True

    def _cancelled(self):
        if self.status in FINAL_STATUSES:
            return
        if self.mode == "force" or not self.launched:
            message = "已停止后续操作；没有执行任何文件清理"
        else:
            message = "已停止后续操作；已经启动的卸载程序不会被强制关闭"
        self._set("cancelled", "任务已取消", message)
        self.finished_at = time.time()
        self._log("任务已取消", "warn")
        self._write_report()
        self._persist()
        self.jobs._clear_active(self)

    def _fail(self, message: str, *, fallback: bool = False):
        if self.status in FINAL_STATUSES:
            return
        self.fallback_available = bool(
            fallback
            and self.mode == "uninstall"
            and self.app.get("kind") == "registry"
            and not self.app.get("protected")
            and not self.launched
        )
        self._set("failed", "任务失败", message)
        self.finished_at = time.time()
        self._write_report()
        self._persist()
        self.jobs._clear_active(self)

    def prepare_fallback(self) -> bool:
        """Turn a failed uninstall into an audited leftover-scan job."""
        with self.lock:
            if (self.status != "failed" or not self.fallback_available
                    or self.mode != "uninstall"
                    or self.app.get("kind") != "registry"
                    or self.app.get("protected")):
                return False
            self.mode = "force"
            self.fallback_used = True
            self.fallback_available = False
            self.stale_registration = False
            self.status = "starting"
            self.phase = "正在准备仅清理残留"
            self.message = "官方卸载程序未能启动；将重新扫描残留，确认后才会清理"
            self.finished_at = None
            self.still_installed = None
            self.installed_check = None
            self.leftover = None
            self.cleanup_result = None
            self.report_path = None
            self.cancel_event.clear()
            self.recheck_event.clear()
            self._log("已改为仅清理残留模式；不会自动删除任何文件", "warn")
            self.updated_at = time.time()
            return True

    def _finish(self):
        with self.lock:
            if self.status in FINAL_STATUSES:
                return
            self.status = "completed"
            self.phase = "清理完成"
            if self.cleanup_result and self.cleanup_result.get("total"):
                self.message = "清理完成"
            elif not self.message:
                self.message = "任务已完成"
            self.finished_at = time.time()
            self.updated_at = self.finished_at
        self._log("任务完成")
        self._write_report()
        self._persist()
        self.jobs._clear_active(self)

    def _write_report(self):
        try:
            wu.LOG_DIR.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base = wu.LOG_DIR / f"SoftSweep_{stamp}_{self.id}.txt"
            lines = [
                "SoftSweep 净软 · 清理报告",
                "=" * 46,
                f"软件：{self.app.get('name')}",
                f"版本：{self.app.get('version') or '—'}",
                f"发布商：{self.app.get('publisher') or '—'}",
                "任务模式：" + (
                    "官方卸载不可用 → 仅清理残留" if self.fallback_used
                    else "强制清理" if self.mode == "force"
                    else "官方卸载 + 深度清理"
                ),
                f"状态：{STATUS_LABELS.get(self.status, self.status)}",
                f"开始时间：{datetime.fromtimestamp(self.created_at):%Y-%m-%d %H:%M:%S}",
                f"结束时间：{datetime.fromtimestamp(self.finished_at):%Y-%m-%d %H:%M:%S}" if self.finished_at else "结束时间：—",
                f"软件是否仍在已安装列表：{'是' if self.still_installed else ('否' if self.still_installed is not None else '未知')}",
                "",
                "操作记录",
                "-" * 46,
            ]
            for entry in self.logs:
                lines.append(f"{entry['time']}  {entry['message']}")
            if self.cleanup_result:
                lines += ["", "清理结果", "-" * 46]
                for item in self.cleanup_result.get("items", []):
                    mark = "成功" if item.get("ok") else "失败"
                    extra = "" if item.get("ok") else f"：{item.get('error')}"
                    lines.append(f"[{mark}] {item.get('label')} · {item.get('path')}{extra}")
                lines.append("")
                lines.append("删除方式：" + ("永久删除" if self.cleanup_result.get("permanent") else "移入回收站"))
                lines.append(f"处理总量：{self.cleanup_result.get('removed_bytes', 0):,} 字节")
                if self.cleanup_result.get("backup_dir"):
                    lines.append(f"注册表备份：{self.cleanup_result['backup_dir']}")
            lines += ["", "说明：文档、下载、图片等个人资料目录不会被自动清理。"]
            base.write_text("\n".join(lines), encoding="utf-8-sig")
            self.report_path = str(base)
        except Exception as exc:
            self._log(f"写入报告失败：{exc}", "error")


class JobsManager:
    def __init__(self, state_dir: Path | None = None):
        self.lock = threading.RLock()
        self.jobs: dict[str, Job] = {}
        self.active_id: str | None = None
        self.state_dir = Path(state_dir) if state_dir else (wu.DATA_DIR / "jobs")
        self._save_lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)

    def active(self) -> Job | None:
        with self.lock:
            if self.active_id:
                job = self.jobs.get(self.active_id)
                if job and job.active:
                    return job
            return None

    def list(self) -> list[dict]:
        with self.lock:
            items = sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)
            return [j.snapshot(include_leftover=False) for j in items[:20]]

    def start(self, app: dict, mode: str = "uninstall", confirm_name: str = "") -> dict:
        if app.get("protected"):
            return {"ok": False, "error": app.get("protected_reason") or "该软件受保护，不能自动卸载"}
        if mode not in {"uninstall", "force"}:
            return {"ok": False, "error": "未知的操作模式"}
        expected_name = normalize_software_name(app.get("name"))
        if mode == "force" and (
            not expected_name or normalize_software_name(confirm_name) != expected_name
        ):
            return {"ok": False, "error": "强制清理需要输入完整软件名称"}
        if mode == "uninstall" and not app.get("can_uninstall"):
            return {"ok": False, "error": "该软件没有可用的官方卸载命令，请使用「仅清理残留」"}
        with self.lock:
            if self.active_id:
                current = self.jobs.get(self.active_id)
                if current and current.active:
                    return {"ok": False, "error": "已有清理任务正在进行，请等待完成"}
            job = Job(app, mode, self)
            self.jobs[job.id] = job
            self.active_id = job.id
        job.start()
        return {"ok": True, "job": job.snapshot(include_leftover=False)}

    def fallback(self, job: Job) -> dict:
        """Recover a failed uninstall by scanning leftovers in the same job."""
        with self.lock:
            if self.jobs.get(job.id) is not job:
                return {"ok": False, "error": "任务不存在"}
            if self.active_id:
                current = self.jobs.get(self.active_id)
                if current and current.active:
                    return {"ok": False, "error": "已有清理任务正在进行，请等待完成"}
            if not job.prepare_fallback():
                return {"ok": False, "error": "当前任务无法改为仅清理残留"}
            self.active_id = job.id
        job.start()
        return {"ok": True, "job": job.snapshot(include_leftover=False)}

    def _clear_active(self, job: Job):
        with self.lock:
            if self.active_id == job.id:
                self.active_id = None

    def save_job_state(self, snapshot: dict):
        job_id = snapshot.get("id")
        if not isinstance(job_id, str) or not _JOB_ID_RE.match(job_id):
            return
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            target = self.state_dir / f"{job_id}.json"
            temp = self.state_dir / f"{job_id}.{os.getpid()}.tmp"
            body = json.dumps(snapshot, ensure_ascii=False, indent=2)
            with self._save_lock:
                temp.write_text(body, encoding="utf-8")
                os.replace(temp, target)
        except OSError:
            pass

    def restore_saved(self) -> int:
        """Restore persisted jobs after a restart. Only an awaiting-confirmation job becomes active."""
        with self.lock:
            if self.jobs:
                return 0
            try:
                files = sorted(
                    self.state_dir.glob("j*.json"),
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                )
            except OSError:
                return 0

            restored: list[Job] = []
            for path in files[:50]:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    continue
                job = Job.from_snapshot(data, self)
                if job:
                    restored.append(job)

            restored.sort(key=lambda job: job.created_at, reverse=True)
            self.active_id = None
            for job in restored:
                if job.status == "awaiting_cleanup" and self.active_id is None:
                    self.active_id = job.id
                    job.message = job.message or "已恢复上次未完成的清理任务"
                    job._log("程序重启后已恢复此任务，仍等待用户确认才会清理", "warn")
                elif job.status not in FINAL_STATUSES:
                    job.status = "failed"
                    job.phase = "任务已中断"
                    job.message = (
                        "程序重启导致任务中断；请重新扫描确认残留文件，再创建新的清理任务"
                    )
                    job.finished_at = time.time()
                    job._log("程序重启，任务已中断", "warn")
                self.jobs[job.id] = job
                self.save_job_state(job.snapshot())
            return len(restored)

    def refresh_main_scan(self):
        def worker():
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                try:
                    if SCANNER.start():
                        return
                except Exception:
                    traceback.print_exc()
                    return
                time.sleep(1.0)

        threading.Thread(target=worker, daemon=True, name="softsweep-refresh").start()


JOBS = JobsManager()
