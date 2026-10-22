"""SoftSweep local desktop application server (Python standard library only)."""
from __future__ import annotations

import argparse
import ctypes
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from core import icons as ICONS
from core import winutil as wu
from core.jobs import JOBS
from core.scanner import SCANNER

APP_VERSION = "1.1.0"
INSTANCE_MUTEX_NAME = "Local\\SoftSweep.SingleInstance.9D4A2B6F"
ERROR_ALREADY_EXISTS = 183
WEB_DIR = wu.APP_DIR / "web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
MAX_BODY = 1024 * 1024
_APP_BROWSER_PROCESS: subprocess.Popen | None = None


def _json_bytes(payload) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, token: str):
        super().__init__(address, handler)
        self.token = token
        self.started_at = time.time()


class Handler(BaseHTTPRequestHandler):
    server_version = "SoftSweep/1.1"
    sys_version = ""

    # ------------------------------------------------------------- utilities
    @property
    def token(self) -> str:
        return self.server.token

    def log_message(self, fmt, *args):
        try:
            line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {self.address_string()} {fmt % args}\n"
            with open(wu.LOG_DIR / "server.log", "a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception:
            pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        allowed = {
            f"127.0.0.1:{self.server.server_port}",
            f"localhost:{self.server.server_port}",
        }
        return host in allowed

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        allowed = {
            f"http://127.0.0.1:{self.server.server_port}",
            f"http://localhost:{self.server.server_port}",
        }
        return origin.rstrip("/") in allowed

    def _auth_ok(self) -> bool:
        supplied = self.headers.get("X-Token") or ""
        if not supplied:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path.startswith("/api/icon/"):
                values = urllib.parse.parse_qs(parsed.query)
                supplied = (values.get("t") or [""])[0]
        return bool(supplied) and hmac.compare_digest(supplied, self.token)

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None,
              cache_control: str = "no-store"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, status: int, payload):
        self._send(status, _json_bytes(payload), "application/json; charset=utf-8")

    def _error(self, status: int, message: str):
        self._json(status, {"ok": False, "error": message})

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("请求内容过大")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("请求格式无效") from exc
        if not isinstance(data, dict):
            raise ValueError("请求格式无效")
        return data

    def _guard(self, *, require_auth: bool = True) -> bool:
        if not self._host_ok():
            self._error(HTTPStatus.FORBIDDEN, "非法的主机地址")
            return False
        if require_auth and not self._auth_ok():
            self._error(HTTPStatus.UNAUTHORIZED, "访问令牌无效，请从启动窗口重新打开界面")
            return False
        if self.command == "POST" and not self._origin_ok():
            self._error(HTTPStatus.FORBIDDEN, "请求来源不受信任")
            return False
        return True

    # ----------------------------------------------------------------- routes
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            if not self._guard():
                return
            try:
                self._api_get(path)
            except Exception as exc:
                traceback.print_exc()
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"服务器错误：{exc}")
            return
        if path in STATIC_FILES:
            filename, ctype = STATIC_FILES[path]
            file_path = WEB_DIR / filename
            try:
                body = file_path.read_bytes()
            except OSError:
                self._error(HTTPStatus.NOT_FOUND, "界面文件缺失")
                return
            self._send(HTTPStatus.OK, body, ctype)
            return
        self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "接口不存在")
            return
        if not self._guard():
            return
        try:
            data = self._read_json()
            self._api_post(path, data)
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:
            traceback.print_exc()
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"服务器错误：{exc}")

    def _api_get(self, path: str):
        if path.startswith("/api/icon/"):
            app_id = path[len("/api/icon/"):]
            if not ICONS.valid_app_id(app_id):
                self._error(HTTPStatus.NOT_FOUND, "图标不存在")
                return
            try:
                body = ICONS.icon_path(app_id).read_bytes()
            except OSError:
                self._error(HTTPStatus.NOT_FOUND, "图标尚未生成")
                return
            if not body.startswith(b"\x89PNG\r\n\x1a\n"):
                self._error(HTTPStatus.NOT_FOUND, "图标文件无效")
                return
            self._send(
                HTTPStatus.OK, body, "image/png",
                cache_control="private, max-age=31536000, immutable",
            )
            return
        if path == "/api/state":
            snap = SCANNER.snapshot()
            active = JOBS.active()
            snap.update({
                "ok": True,
                "version": APP_VERSION,
                "jobs_active": active.snapshot(include_leftover=False) if active else None,
                "jobs_history": JOBS.list(),
            })
            self._json(HTTPStatus.OK, snap)
            return
        if path == "/api/jobs":
            self._json(HTTPStatus.OK, {"ok": True, "jobs": JOBS.list()})
            return
        if path.startswith("/api/jobs/"):
            parts = [p for p in path.split("/") if p]
            # /api/jobs/<id> or /api/jobs/<id>/report
            if len(parts) == 3:
                job = JOBS.get(parts[2])
                if not job:
                    self._error(HTTPStatus.NOT_FOUND, "任务不存在")
                    return
                self._json(HTTPStatus.OK, {"ok": True, "job": job.snapshot()})
                return
            if len(parts) == 4 and parts[3] == "report":
                job = JOBS.get(parts[2])
                if not job or not job.report_path:
                    self._error(HTTPStatus.NOT_FOUND, "报告尚未生成")
                    return
                report = Path(job.report_path)
                if not report.exists():
                    self._error(HTTPStatus.NOT_FOUND, "报告文件不存在")
                    return
                body = report.read_bytes()
                name = urllib.parse.quote(report.name)
                self._send(
                    HTTPStatus.OK, body, "text/plain; charset=utf-8",
                    {"Content-Disposition": f"attachment; filename*=UTF-8''{name}"},
                )
                return
        self._error(HTTPStatus.NOT_FOUND, "接口不存在")

    def _api_post(self, path: str, data: dict):
        if path == "/api/scan":
            started = SCANNER.start()
            self._json(HTTPStatus.OK, {"ok": True, "started": started})
            return
        if path == "/api/jobs":
            app_id = str(data.get("app_id") or "")
            mode = str(data.get("mode") or "uninstall")
            confirm = str(data.get("confirm_name") or "")
            app = SCANNER.get_app(app_id)
            if not app:
                self._error(HTTPStatus.NOT_FOUND, "软件不存在，请重新扫描")
                return
            result = JOBS.start(app, mode, confirm)
            if not result.get("ok"):
                self._error(HTTPStatus.CONFLICT, result.get("error") or "无法创建任务")
                return
            self._json(HTTPStatus.OK, result)
            return
        if path.startswith("/api/jobs/"):
            parts = [p for p in path.split("/") if p]
            if len(parts) == 4:
                job = JOBS.get(parts[2])
                if not job:
                    self._error(HTTPStatus.NOT_FOUND, "任务不存在")
                    return
                action = parts[3]
                if action == "recheck":
                    ok = job.recheck()
                    if not ok:
                        self._error(HTTPStatus.CONFLICT, "当前阶段无法重新检查")
                        return
                    self._json(HTTPStatus.OK, {"ok": True, "job": job.snapshot(include_leftover=False)})
                    return
                if action == "cancel":
                    ok = job.cancel()
                    if not ok:
                        self._error(HTTPStatus.CONFLICT, "任务已结束")
                        return
                    self._json(HTTPStatus.OK, {"ok": True, "job": job.snapshot(include_leftover=False)})
                    return
                if action == "cleanup":
                    item_ids = data.get("item_ids") or []
                    if not isinstance(item_ids, list) or not all(isinstance(i, str) for i in item_ids):
                        self._error(HTTPStatus.BAD_REQUEST, "项目列表无效")
                        return
                    permanent = bool(data.get("permanent"))
                    confirm = str(data.get("confirm_name") or "")
                    result = job.cleanup(item_ids, permanent=permanent, confirm_name=confirm)
                    if not result.get("ok"):
                        self._error(HTTPStatus.CONFLICT, result.get("error") or "清理失败")
                        return
                    self._json(HTTPStatus.OK, {"ok": True, "job": job.snapshot()})
                    return
        if path == "/api/open-report-folder":
            job_id = str(data.get("job_id") or "")
            job = JOBS.get(job_id)
            if not job or not job.report_path:
                self._error(HTTPStatus.NOT_FOUND, "报告尚未生成")
                return
            try:
                wu.open_local_path(Path(job.report_path).parent)
            except Exception as exc:
                self._error(HTTPStatus.BAD_REQUEST, f"无法打开文件夹：{exc}")
                return
            self._json(HTTPStatus.OK, {"ok": True})
            return
        if path == "/api/quit":
            self._json(HTTPStatus.OK, {"ok": True, "message": "SoftSweep 即将退出"})
            _request_app_shutdown(self.server)
            return
        self._error(HTTPStatus.NOT_FOUND, "接口不存在")


def _redirect_stdout_for_pythonw():
    """pythonw has no console; keep a log file instead of crashing on writes."""
    if sys.stdout is None or sys.stderr is None:
        log = open(wu.LOG_DIR / "server-output.log", "a", encoding="utf-8", buffering=1)
        if sys.stdout is None:
            sys.stdout = log
        if sys.stderr is None:
            sys.stderr = log


def _acquire_instance_mutex():
    try:
        mutex = ctypes.windll.kernel32.CreateMutexW(None, False, INSTANCE_MUTEX_NAME)
        if not mutex:
            return True, None
        if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            ctypes.windll.kernel32.CloseHandle(mutex)
            return False, None
        return True, mutex
    except Exception:
        return True, None


def _load_session() -> dict | None:
    try:
        session = json.loads((wu.DATA_DIR / "session.json").read_text(encoding="utf-8"))
        port = int(session.get("port") or 0)
        if port and str(session.get("url") or "").startswith("http://127.0.0.1:"):
            return session
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        pass
    return None


def _server_is_ready(port: int, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.08)
    return False


def _chromium_executable() -> Path | None:
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    local = wu.LOCAL_APPDATA if hasattr(wu, "LOCAL_APPDATA") else Path(
        os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
    )
    candidates = (
        pf / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        pf86 / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        local / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        pf / "Google" / "Chrome" / "Application" / "chrome.exe",
        pf86 / "Google" / "Chrome" / "Application" / "chrome.exe",
        local / "Google" / "Chrome" / "Application" / "chrome.exe",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _open_app_window(url: str, *, wait_for_exit: bool) -> subprocess.Popen | None:
    """Open an Edge/Chrome application-style window, falling back to the default browser."""
    browser = _chromium_executable()
    if browser:
        profile_dir = wu.DATA_DIR / "app-browser"
        args = [
            str(browser),
            f"--app={url}",
            f"--user-data-dir={profile_dir}",
            "--window-size=1320,880",
            "--window-position=50,50",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        try:
            proc = subprocess.Popen(args)
            if not wait_for_exit:
                return None
            return proc
        except OSError:
            pass
    threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    return None


def _request_app_shutdown(server: AppServer):
    threading.Thread(target=server.shutdown, daemon=True).start()
    proc = _APP_BROWSER_PROCESS
    if not proc or proc.poll() is not None:
        return

    def close_browser():
        try:
            time.sleep(0.15)
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    threading.Thread(target=close_browser, daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser(description="SoftSweep local server")
    parser.add_argument("--port", type=int, default=0, help="0 chooses a free port")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    if not (WEB_DIR / "index.html").exists():
        print("缺少 web/index.html，无法启动界面", file=sys.stderr)
        return 2

    acquired, instance_mutex = _acquire_instance_mutex()
    if not acquired:
        session = _load_session()
        if session and _server_is_ready(int(session["port"]), timeout=1.0):
            _open_app_window(session["url"], wait_for_exit=False)
            print("SoftSweep 已在运行，已打开新的应用窗口")
            return 0

    restored_jobs = JOBS.restore_saved()
    if restored_jobs:
        print(f"已恢复 {restored_jobs} 个历史清理任务")
    token = secrets.token_urlsafe(32)
    try:
        server = AppServer(("127.0.0.1", args.port), Handler, token)
    except OSError as exc:
        print(f"无法监听本机端口：{exc}", file=sys.stderr)
        return 3
    port = server.server_port
    url = f"http://127.0.0.1:{port}/?t={token}"
    session = {
        "url": url,
        "port": port,
        "pid": os.getpid(),
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": APP_VERSION,
        "is_admin": wu.is_admin(),
        "mode": "app" if _chromium_executable() else "browser",
    }
    try:
        (wu.DATA_DIR / "session.json").write_text(
            json.dumps(session, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        pass
    print(f"SoftSweep 已启动：{url}")
    print(f"管理员权限：{'是' if wu.is_admin() else '否（部分功能需要管理员）'}")

    server_thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.25},
        daemon=True, name="softsweep-server",
    )
    server_thread.start()
    global _APP_BROWSER_PROCESS
    browser_proc = None
    try:
        if _server_is_ready(port) and not args.no_browser:
            browser_proc = _open_app_window(url, wait_for_exit=True)
            _APP_BROWSER_PROCESS = browser_proc
        if browser_proc:
            launched_at = time.monotonic()
            browser_proc.wait()
            # A browser launcher sometimes hands off and exits immediately.
            # Only treat a short-lived process as the user closing the app.
            if time.monotonic() - launched_at > 2:
                server.shutdown()
        server_thread.join()
    except KeyboardInterrupt:
        server.shutdown()
        server_thread.join(timeout=2)
    finally:
        server.server_close()
        try:
            (wu.DATA_DIR / "session.json").unlink(missing_ok=True)
        except OSError:
            pass
        if instance_mutex:
            try:
                ctypes.windll.kernel32.ReleaseMutex(instance_mutex)
                ctypes.windll.kernel32.CloseHandle(instance_mutex)
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    _redirect_stdout_for_pythonw()
    raise SystemExit(main())
