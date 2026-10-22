"""SoftSweep 隔离安全自检。

只会在当前用户的 AppData\\Local 下创建临时目录，并在 HKCU\\Software 下
创建临时注册表项。不会触碰真实软件、个人文档或现有注册表内容。
运行：python tests/selftest.py
"""
from __future__ import annotations

import os
import shutil
import sys
import time
import winreg
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import icons  # noqa: E402
from core import jobs as job_engine  # noqa: E402
from core import scanner as scan_engine  # noqa: E402
from core import winutil as wu  # noqa: E402

runner = "SoftSweepSelfTest_{}_{}".format(os.getpid(), int(time.time()))
TEST_ROOT = wu.LOCAL_APPDATA / runner
TEST_KEY = rf"HKCU\Software\{runner}\Product"
BACKUP_FILE = TEST_ROOT / "backup" / "self-test.reg"

results: list[tuple[bool, str, str]] = []


def check(condition: bool, name: str, detail: str = "") -> None:
    results.append((bool(condition), name, detail))


def expect_refused(value: bool, name: str) -> None:
    check(not value, name, "应当拒绝，但返回了允许")


def setup() -> None:
    TEST_ROOT.mkdir(parents=True, exist_ok=False)
    (TEST_ROOT / "recycle_me").mkdir()
    (TEST_ROOT / "recycle_me" / "payload.txt").write_text("recycle", encoding="utf-8")
    (TEST_ROOT / "permanent_me").mkdir()
    (TEST_ROOT / "permanent_me" / "payload.txt").write_text("permanent", encoding="utf-8")
    (TEST_ROOT / "ordinary.txt").write_text("not a shortcut", encoding="utf-8")
    (TEST_ROOT / "fake.lnk").write_bytes(b"not a real shortcut")

    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, rf"Software\{runner}\Product", 0, winreg.KEY_WRITE
    ) as key:
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "SoftSweep Self Test")
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, "self-test")
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, rf"Software\{runner}\Product\Child", 0, winreg.KEY_WRITE
    ) as key:
        winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, "child")


def registry_exists() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"Software\{runner}\Product"):
            return True
    except FileNotFoundError:
        return False


def test_safe_paths() -> None:
    expect_refused(wu.is_safe_dir_path(wu.WINDOWS_DIR / "System32"), "拒绝系统目录")
    expect_refused(wu.is_safe_dir_path(wu.PROGRAM_FILES), "拒绝 Program Files 根目录")
    expect_refused(wu.is_safe_dir_path(wu.PROGRAM_DATA), "拒绝 ProgramData 根目录")
    expect_refused(wu.is_safe_dir_path(wu.USER_PROFILE), "拒绝用户主目录")
    expect_refused(wu.is_safe_dir_path(wu.USER_PROFILE / "Documents"), "拒绝个人文档目录")
    expect_refused(wu.is_safe_dir_path(wu.USER_PROFILE / "Downloads"), "拒绝下载目录")
    expect_refused(wu.is_safe_dir_path(wu.LOCAL_APPDATA), "拒绝 AppData\\Local 根目录")
    expect_refused(wu.is_safe_dir_path(wu.DATA_DIR), "拒绝工具自己的 data 目录")
    expect_refused(wu.is_safe_dir_path(wu.APP_DIR), "拒绝工具目录")
    expect_refused(wu.is_safe_dir_path(wu.APP_DIR.parent), "拒绝工具目录的父目录")
    expect_refused(wu.is_safe_dir_path(TEST_ROOT / "missing"), "拒绝不存在的路径")
    expect_refused(wu.is_safe_dir_path(TEST_ROOT / "ordinary.txt"), "拒绝普通文件路径")
    check(wu.is_safe_dir_path(TEST_ROOT / "recycle_me"), "允许隔离测试目录")
    check(wu.is_safe_dir_path(TEST_ROOT / "recycle_me", trusted=True), "允许 trusted 隔离目录")
    expect_refused(
        wu.is_safe_shortcut_path(TEST_ROOT / "fake.lnk"), "拒绝非快捷方式安全根目录下的 .lnk"
    )


def test_delete_refusals() -> None:
    result = wu.delete_path(TEST_ROOT / "ordinary.txt")
    check(not result.get("ok") and (TEST_ROOT / "ordinary.txt").exists(),
          "delete_path 拒绝普通文件", str(result))
    result = wu.delete_path(TEST_ROOT / "fake.lnk")
    check(not result.get("ok") and (TEST_ROOT / "fake.lnk").exists(),
          "delete_path 拒绝不安全快捷方式", str(result))


def test_recycle_and_permanent() -> None:
    recycle_dir = TEST_ROOT / "recycle_me"
    result = wu.delete_path(recycle_dir, permanent=False)
    check(result.get("ok") and not recycle_dir.exists() and result.get("recycled"),
          "目录移入回收站", str(result))

    permanent_dir = TEST_ROOT / "permanent_me"
    result = wu.delete_path(permanent_dir, permanent=True)
    check(result.get("ok") and not permanent_dir.exists() and result.get("recycled") is False,
          "目录永久删除（隔离目录）", str(result))


def test_registry() -> None:
    check(wu.is_safe_registry_key(TEST_KEY), "允许隔离 HKCU 测试项")
    check(registry_exists(), "测试注册表项已创建")
    backup = wu.delete_registry_key(TEST_KEY, BACKUP_FILE)
    check(backup.get("ok") and not registry_exists(), "注册表备份后删除测试项", str(backup))
    check(BACKUP_FILE.exists() and BACKUP_FILE.stat().st_size > 0,
          "注册表备份文件已生成", str(BACKUP_FILE))
    text = BACKUP_FILE.read_text(encoding="utf-16-le", errors="ignore") if BACKUP_FILE.exists() else ""
    check(runner in text, "备份文件包含测试项名称")

    expect_refused(
        wu.is_safe_registry_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
        "拒绝系统启动项",
    )
    expect_refused(wu.is_safe_registry_key(r"HKLM\SYSTEM\CurrentControlSet"), "拒绝 HKLM\\SYSTEM")
    expect_refused(wu.is_safe_registry_key(r"HKLM\SOFTWARE"), "拒绝 HKLM\\SOFTWARE 根")
    fake = rf"HKCU\Software\Microsoft\Windows\CurrentVersion\{runner}"
    refused = wu.delete_registry_key(fake, TEST_ROOT / "backup" / "never.reg")
    check(not refused.get("ok") and "安全策略" in str(refused.get("error")),
          "delete_registry_key 拒绝受保护分支", str(refused))

    check(wu.is_safe_run_value(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", runner),
        "允许隔离 Run 值名称")
    expect_refused(wu.is_safe_run_value(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Path"),
        "拒绝 Path 启动值")
    expect_refused(wu.is_safe_run_value(
        r"HKCU\Software\SoftSweepSelfTest\Run", runner),
        "拒绝非系统 Run 键路径")


def make_leftover(path: Path, item_id: str) -> dict:
    return {
        "app_name": "SoftSweep Self Test",
        "items": [{
            "id": item_id,
            "kind": "dir",
            "section": "install",
            "label": "测试目录",
            "path": str(path),
            "display_path": str(path),
            "bytes": 9,
            "value_name": "",
        }],
        "sections": [],
        "selected_bytes": 9,
        "all_bytes": 9,
        "notice": [],
    }


def make_test_job(name: str, manager: job_engine.JobsManager) -> job_engine.Job:
    app = {
        "id": "a0123456789abcde",
        "kind": "registry",
        "name": name,
        "version": "1.0",
        "publisher": "SoftSweep",
        "protected": False,
        "can_uninstall": False,
    }
    return job_engine.Job(app, "force", manager)


def test_job_cleanup_and_recovery() -> None:
    permanent_path = TEST_ROOT / "job_permanent"
    recycled_path = TEST_ROOT / "job_recycle"
    restored_path = TEST_ROOT / "job_restored"
    for directory in (permanent_path, recycled_path, restored_path):
        directory.mkdir(parents=True, exist_ok=False)
        (directory / "payload.txt").write_text("softsweep", encoding="utf-8")

    old_backup_dir = wu.BACKUP_DIR
    old_log_dir = wu.LOG_DIR
    wu.BACKUP_DIR = TEST_ROOT / "job-backups"
    wu.LOG_DIR = TEST_ROOT / "job-reports"
    state_dir = TEST_ROOT / "job-state"
    try:
        manager = job_engine.JobsManager(state_dir)
        first = make_test_job("SoftSweep Self Test", manager)
        check(callable(getattr(first, "cleanup", None)),
              "Job.cleanup 没有被 cleanup_result 属性覆盖")
        first.status = "awaiting_cleanup"
        first.leftover = make_leftover(permanent_path, "test-permanent")

        rejected = first.cleanup(["test-permanent"], permanent=True, confirm_name="错误名称")
        check(not rejected.get("ok") and permanent_path.exists(),
              "永久清理仍需正确软件名称", str(rejected))

        confirmed = first.cleanup(["test-permanent"], permanent=True,
                                  confirm_name="SoftSweep Self Test")
        check(confirmed.get("ok") and not permanent_path.exists(),
              "Job.cleanup 永久删除隔离测试目录", str(confirmed))
        check(first.status == "completed" and first.cleanup_result is not None,
              "Job.cleanup 完成后写入结果", str(first.status))
        report_exists = bool(first.report_path and Path(first.report_path).exists())
        check(report_exists, "Job.cleanup 完成报告已生成", str(first.report_path))

        second = make_test_job("SoftSweep Recovery Test", manager)
        second.status = "awaiting_cleanup"
        second.leftover = make_leftover(restored_path, "test-restored")
        second._persist()
        state_file = state_dir / f"{second.id}.json"
        check(state_file.exists(), "待确认任务已持久化", str(state_file))

        recovered_manager = job_engine.JobsManager(state_dir)
        restored_count = recovered_manager.restore_saved()
        recovered = recovered_manager.get(second.id)
        check(restored_count >= 1 and recovered is not None,
              "重启后的任务快照可以恢复", str(restored_count))
        check(bool(recovered) and recovered.status == "awaiting_cleanup",
              "恢复任务仍保持待确认状态", getattr(recovered, "status", ""))
        check(bool(recovered) and recovered_manager.active_id == recovered.id,
              "恢复任务可以重新成为活动任务")
        check(bool(recovered) and recovered.leftover and
              recovered.leftover["items"][0]["id"] == "test-restored",
              "恢复任务保留原残留清单")
        check(bool(recovered) and recovered.app.get("name") == "SoftSweep Recovery Test",
              "恢复任务保留原软件名称")

        recycled = second.cleanup(["test-restored"], permanent=False)
        check(recycled.get("ok") and not restored_path.exists(),
              "原待确认任务可以直接回收", str(recycled))

        recovered_cleanup = recovered.cleanup if recovered else None
        check(callable(recovered_cleanup), "恢复后的 Job.cleanup 仍可调用")
    finally:
        wu.BACKUP_DIR = old_backup_dir
        wu.LOG_DIR = old_log_dir


def test_icon_boundaries() -> None:
    check(icons.valid_app_id("a0123456789abcdef"), "接受合法应用 ID")
    for bad in ("", "../x", "a0123", "j0123456789abcdef", "u0123456789ABCDEF", "../../a0123456789abcdef"):
        expect_refused(icons.valid_app_id(bad), f"拒绝非法应用 ID {bad!r}")


def test_size_probe_safety() -> None:
    """Folder inference may only ever point at one product's own directory."""
    pf = str(wu.PROGRAM_FILES)
    leaf = scan_engine._looks_like_app_leaf
    expect_refused(leaf(pf), "拒绝 Program Files 根目录")
    expect_refused(leaf(str(wu.SYSTEM_DRIVE)), "拒绝系统盘根目录")
    expect_refused(leaf(str(wu.LOCAL_APPDATA)), "拒绝 AppData\\Local 根目录")
    expect_refused(leaf(pf + "\\SomeVendor"), "拒绝厂商共享目录（名称不匹配软件）")
    expect_refused(leaf(pf + "\\Common Files"), "拒绝公共组件目录")
    expect_refused(leaf(pf + "\\SomeVendor\\data"), "拒绝 data 之类的子目录")
    check(leaf(pf + "\\SomeVendor\\SomeApp"), "接受厂商目录下的具体应用目录")
    check(leaf(pf + "\\Microsoft OneDrive", {"microsoftonedrive"}), "名称与软件一致时接受一级目录")

    normalise = scan_engine._normalise_probe_folder
    check(normalise(pf + "\\SomeApp\\bin\\app.exe") == pf + "\\SomeApp", "从 bin 子目录回到应用目录",
          normalise(pf + "\\SomeApp\\bin\\app.exe"))
    check(not normalise(pf + "\\SomeApp\\data\\icon").endswith("icon"), "跳出 data/icon 这类资源目录")
    check(normalise(str(TEST_ROOT) + "\\payload.txt") == str(TEST_ROOT), "文件同级目录即应用目录")

    apps = [
        {"id": "a1", "kind": "registry", "protected": False, "install_location": str(TEST_ROOT / "host"),
         "location_exists": True, "size_state": "computing", "size_probe_path": ""},
        {"id": "a2", "kind": "registry", "protected": False, "install_location": "",
         "location_exists": False, "size_state": "unknown",
         "size_probe_path": str(TEST_ROOT)},
        {"id": "a3", "kind": "registry", "protected": False, "install_location": "",
         "location_exists": False, "size_state": "unknown",
         "size_probe_path": str(TEST_ROOT / "only_app")},
    ]
    (TEST_ROOT / "host").mkdir()
    (TEST_ROOT / "only_app").mkdir()
    scan_engine._validate_size_probes(apps)
    expect_refused(bool(apps[1]["size_probe_path"]), "包含其他软件安装目录的推断结果被丢弃")
    check(apps[1]["size_state"] == "unknown", "被丢弃后保持未知状态")
    check(apps[2]["size_probe_path"] == str(TEST_ROOT / "only_app"), "独立的应用目录被保留")
    check(apps[2]["size_state"] == "computing", "保留的推断目录进入统计队列")


def test_store_app_size_and_publisher() -> None:
    """Store apps must report a real size instead of a placeholder."""
    install = TEST_ROOT / "store_install"
    data = TEST_ROOT / "store_data"
    install.mkdir()
    data.mkdir()
    (install / "app.exe").write_bytes(b"x" * 4096)
    (data / "state.db").write_bytes(b"y" * 8192)

    manager = scan_engine.ScanManager()
    app = {
        "kind": "uwp",
        "install_location": str(install),
        "package_data_path": str(data),
        "location_exists": True,
    }
    measurement = manager._measure_app_size(app)
    check(measurement["total"] == 4096 + 8192, "商店应用大小等于安装目录加应用数据", str(measurement))
    check(measurement["denied"] is False, "商店应用目录可读时不标记为无权限")

    nested = dict(app, package_data_path=str(install))
    check(manager._measure_app_size(nested)["data_bytes"] is None, "应用数据位于安装目录内时不重复计算")

    missing = {
        "kind": "uwp",
        "install_location": str(TEST_ROOT / "does_not_exist"),
        "package_data_path": "",
        "location_exists": True,
    }
    gone = manager._measure_app_size(missing)
    check(gone["total"] is None and gone["install_bytes"] is None,
          "目录缺失且无推断时不显示 0 字节", str(gone))

    cases = [
        (("OpenAI.Codex", "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B", ""), "OpenAI"),
        (("OpenAI.Codex", "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B", "OpenAI Inc."), "OpenAI Inc."),
        (("Intel.Graphic", "CN=INTEL CORP, OU=Testing, O=Intel", ""), "INTEL CORP"),
    ]
    for args, expected in cases:
        got = scan_engine._uwp_publisher(*args)
        check(got == expected, f"商店应用发布商解析为「{expected}」", f"实际：{got}")

    apps, warnings = scan_engine.scan_uwp_apps()
    if not apps:
        check(False, "读取本机商店应用列表", "；".join(warnings) or "未返回任何应用")
        return
    check(all(a["size_state"] == "computing" and a["size"]["computing"] for a in apps),
          "商店应用登记为待统计状态")
    check(all(a["install_location_display"] == a["install_location"] for a in apps),
          "商店应用显示真实安装路径")
    guidish = [a["name"] for a in apps if scan_engine._GUID_RE.fullmatch(a["publisher"] or "")]
    check(not guidish, "商店应用发布商不显示证书 GUID", "、".join(guidish[:5]))
    measured = [manager._measure_app_size(a) for a in apps]
    with_size = sum(1 for m in measured if (m["total"] or 0) > 0)
    check(with_size >= max(1, len(apps) // 2), "多数商店应用可以统计到大小", f"{with_size}/{len(apps)}")


def cleanup() -> None:
    try:
        wu._delete_reg_tree(winreg.HKEY_CURRENT_USER, rf"Software\{runner}")
    except OSError:
        pass
    shutil.rmtree(TEST_ROOT, ignore_errors=True)


def main() -> int:
    print("SoftSweep 隔离安全自检")
    print(f"测试目录：{TEST_ROOT}")
    print(f"测试注册表：{TEST_KEY}")
    print("-" * 68)
    try:
        setup()
        test_safe_paths()
        test_delete_refusals()
        test_recycle_and_permanent()
        test_registry()
        test_job_cleanup_and_recovery()
        test_store_app_size_and_publisher()
        test_size_probe_safety()
        test_icon_boundaries()
    except Exception as exc:
        check(False, "自检执行异常", f"{type(exc).__name__}: {exc}")
    finally:
        cleanup()

    failed = 0
    for ok, name, detail in results:
        mark = "通过" if ok else "失败"
        print(f"[{mark}] {name}" + (f"  {detail}" if detail and not ok else ""))
        if not ok:
            failed += 1
    print("-" * 68)
    print(f"共 {len(results)} 项，通过 {len(results) - failed} 项，失败 {failed} 项。")
    if failed:
        print("注意：失败项需要修复后再交付。")
        return 1
    print("所有安全边界测试通过。回收站测试目录已移入回收站，可手动清空。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
