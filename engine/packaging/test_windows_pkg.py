#!/usr/bin/env python3
"""Windows packaging acceptance tests (P-1 through P-9, plus WITH_UI=ON status).

Runs on the GitHub Actions `windows-latest` runner against the staged install tree
and the built Inno Setup per-user installer. Prints one clear status line per case:
`PASS  P-x ...`, `FAIL  P-x ...`, or `NOT RUN  ...` with reason.
"""
from __future__ import annotations

import argparse
import csv
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import winreg
from pathlib import Path

from common_checks import (
    check_licenses_and_notices,
    check_wording,
    find_created_keys_or_signatures,
)

APP_UNINSTALL_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    r"\{8E4C7D1A-5F23-4B9E-A612-3D9E40F5C8B2}_is1"
)
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

results: list[tuple[str, str, str]] = []


def record(case_id: str, status: str, detail: str) -> None:
    assert status in ("PASS", "FAIL", "NOT RUN")
    print(f"{status}  {case_id}: {detail}", flush=True)
    results.append((case_id, status, detail))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- Non-elevated execution via Windows SAFER normal-user token --------------------

SAFER_SCOPEID_USER = 2
SAFER_LEVELID_NORMALUSER = 0x20000
SAFER_LEVEL_OPEN = 1
CREATE_UNICODE_ENVIRONMENT = 0x00000400
INFINITE = 0xFFFFFFFF


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def run_as_standard_user(args: list[str], timeout_sec: int = 180) -> tuple[int, bool]:
    """Run `args` using a SAFER normal-user (non-elevated) token.

    Returns `(exit_code, used_safer_token)`.
    """
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    advapi32.SaferCreateLevel.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.LPVOID,
    ]
    advapi32.SaferCreateLevel.restype = wintypes.BOOL
    advapi32.SaferComputeTokenFromLevel.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    advapi32.SaferComputeTokenFromLevel.restype = wintypes.BOOL
    advapi32.SaferCloseLevel.argtypes = [wintypes.HANDLE]
    advapi32.SaferCloseLevel.restype = wintypes.BOOL
    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    advapi32.CreateProcessAsUserW.restype = wintypes.BOOL

    level = wintypes.HANDLE()
    token = wintypes.HANDLE()
    if not advapi32.SaferCreateLevel(
        SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, ctypes.byref(level), None
    ):
        err = ctypes.get_last_error()
        raise RuntimeError(f"SaferCreateLevel failed with error {err}")

    try:
        if not advapi32.SaferComputeTokenFromLevel(
            level, None, ctypes.byref(token), 0, None
        ):
            err = ctypes.get_last_error()
            raise RuntimeError(f"SaferComputeTokenFromLevel failed with error {err}")

        cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(args))
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        pi = PROCESS_INFORMATION()

        ok = advapi32.CreateProcessAsUserW(
            token,
            None,
            cmdline,
            None,
            None,
            False,
            0,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            # Fallback with __COMPAT_LAYER=RunAsInvoker if runner policy restricts CreateProcessAsUserW
            env = os.environ.copy()
            env["__COMPAT_LAYER"] = "RUNASINVOKER"
            proc = subprocess.run(args, env=env, timeout=timeout_sec)
            return proc.returncode, False

        try:
            wait_res = kernel32.WaitForSingleObject(
                pi.hProcess, int(timeout_sec * 1000)
            )
            if wait_res != 0:
                kernel32.TerminateProcess(pi.hProcess, 1)
                raise TimeoutError(f"Process timed out: {args}")
            exit_code = wintypes.DWORD()
            kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
            return int(exit_code.value), True
        finally:
            kernel32.CloseHandle(pi.hThread)
            kernel32.CloseHandle(pi.hProcess)
    finally:
        if token.value:
            kernel32.CloseHandle(token)
        advapi32.SaferCloseLevel(level)


def read_reg_values(root: int, subkey: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            idx = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, idx)
                    values[name] = str(val)
                    idx += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    return values


def reg_key_exists(root: int, subkey: str) -> bool:
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False


def snapshot_user_and_system_state() -> dict[str, set[str] | dict[str, str]]:
    """Snapshot relevant user/system filesystem locations and Run registry keys."""
    local_app = Path(os.environ["LOCALAPPDATA"]).resolve()
    roaming_app = Path(os.environ["APPDATA"]).resolve()
    user_profile = Path(os.environ["USERPROFILE"]).resolve()

    local_skip_top = {
        "temp",
        "microsoft",
        "packages",
        "crashdumps",
        "d3dscache",
        "connecteddevicesplatform",
        "comms",
        "publishers",
    }
    roaming_skip_rel = {
        "microsoft/windows/recent",
        "microsoft/crypto",
        "microsoft/protect",
        "microsoft/credentials",
        "microsoft/systemcertificates",
    }

    files: set[str] = set()

    # 1. %LOCALAPPDATA% (excluding OS temp/background telemetry folders)
    if local_app.is_dir():
        for entry in local_app.iterdir():
            if entry.name.lower() in local_skip_top:
                continue
            files.add(os.path.normcase(str(entry)))
            if entry.is_dir():
                for root_str, dirs, fnames in os.walk(entry):
                    rp = Path(root_str)
                    for d in dirs:
                        files.add(os.path.normcase(str(rp / d)))
                    for f in fnames:
                        files.add(os.path.normcase(str(rp / f)))

    # 2. %APPDATA% (including Microsoft\Windows\Start Menu!)
    if roaming_app.is_dir():
        for root_str, dirs, fnames in os.walk(roaming_app):
            rp = Path(root_str)
            rel = rp.relative_to(roaming_app).as_posix().lower()
            if any(rel == s or rel.startswith(s + "/") for s in roaming_skip_rel):
                dirs[:] = []
                continue
            for d in list(dirs):
                child_rel = (rp / d).relative_to(roaming_app).as_posix().lower()
                if any(child_rel == s or child_rel.startswith(s + "/") for s in roaming_skip_rel):
                    dirs.remove(d)
                    continue
                files.add(os.path.normcase(str(rp / d)))
            for f in fnames:
                files.add(os.path.normcase(str(rp / f)))

    # 3. Desktop & All-Users Start Menu & top-level Program Files / ProgramData
    for extra in (
        user_profile / "Desktop",
        Path(r"C:\Users\Public\Desktop"),
        Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs",
    ):
        if extra.is_dir():
            for p in extra.rglob("*"):
                files.add(os.path.normcase(str(p)))

    for sys_top in (
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("ProgramData", r"C:\ProgramData")),
    ):
        if sys_top.is_dir():
            for child in sys_top.iterdir():
                if "dexmond" in child.name.lower() or child.name.lower().startswith("mie"):
                    files.add(os.path.normcase(str(child)))

    return {
        "files": files,
        "hkcu_run": read_reg_values(winreg.HKEY_CURRENT_USER, RUN_KEY),
        "hklm_run": read_reg_values(winreg.HKEY_LOCAL_MACHINE, RUN_KEY),
    }


def running_mie_or_unins_processes() -> list[tuple[str, int]]:
    out = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"],
        check=True,
        capture_output=True,
        text=True,
    )
    procs: list[tuple[str, int]] = []
    for row in csv.reader(io.StringIO(out.stdout)):
        if len(row) >= 2:
            name = row[0].strip()
            low = name.lower()
            if (
                low in ("mie.exe", "mie-service.exe", "mie-ui.exe", "unins000.exe")
                or (low.startswith("_iu") and low.endswith(".tmp"))
            ):
                try:
                    procs.append((name, int(row[1])))
                except ValueError:
                    procs.append((name, -1))
    return procs


def wait_for_uninstall_finish(install_dir: Path, start_menu_dir: Path, timeout_sec: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        active = running_mie_or_unins_processes()
        if not active and not install_dir.exists() and not start_menu_dir.exists():
            time.sleep(0.5)
            return
        time.sleep(0.25)


def find_dumpbin() -> Path:
    pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    vswhere = pf86 / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    out = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    vs_root = Path(out.stdout.strip())
    bins = sorted((vs_root / "VC" / "Tools" / "MSVC").glob("*/bin/Hostx64/x64/dumpbin.exe"))
    if not bins:
        raise RuntimeError("dumpbin.exe not found")
    return bins[-1]


def check_dependents(dumpbin: Path, install_dir: Path) -> tuple[bool, str]:
    sys32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    binaries = sorted(list(install_dir.glob("*.exe")) + list(install_dir.glob("*.dll")))
    binaries = [b for b in binaries if not b.name.lower().startswith("unins")]
    missing: list[str] = []

    for b in binaries:
        out = subprocess.run(
            [str(dumpbin), "/dependents", str(b)],
            check=True,
            capture_output=True,
            text=True,
        )
        in_deps = False
        for line in out.stdout.splitlines():
            s = line.strip()
            if "Image has the following dependencies:" in line:
                in_deps = True
                continue
            if in_deps and s.startswith("Summary"):
                break
            if in_deps and s.lower().endswith(".dll") and " " not in s:
                low = s.lower()
                if (install_dir / s).is_file():
                    continue
                if low.startswith("api-ms-win-") or low.startswith("ext-ms-win-"):
                    # Resolved by Windows ApiSetSchema to System32\ucrtbase.dll / kernelbase.dll
                    if (sys32 / "ucrtbase.dll").is_file():
                        continue
                if (sys32 / s).is_file():
                    continue
                handle = ctypes.windll.kernel32.LoadLibraryExW(s, None, 0x00000802)
                if handle:
                    ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(handle))
                    continue
                missing.append(f"{b.name} -> {s}")

    # Also verify our chosen app-local C++ runtime DLLs sit inside install_dir
    for crt_dll in ("vcruntime140.dll", "msvcp140.dll"):
        if not (install_dir / crt_dll).is_file():
            missing.append(f"expected app-local CRT {crt_dll} not in {install_dir}")

    if missing:
        return False, "missing libraries: " + ", ".join(missing)
    return True, f"all dependents of {len(binaries)} installed binaries resolved against install folder and System32"


def minimal_clean_env() -> dict[str, str]:
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    return {
        "SystemRoot": sys_root,
        "WINDIR": sys_root,
        "PATH": f"{sys_root}\\System32;{sys_root}",
        "LOCALAPPDATA": os.environ["LOCALAPPDATA"],
        "APPDATA": os.environ["APPDATA"],
        "USERPROFILE": os.environ["USERPROFILE"],
        "TEMP": os.environ["TEMP"],
        "TMP": os.environ["TMP"],
    }


def start_and_verify_installed_programs(install_dir: Path) -> tuple[bool, str, subprocess.Popen | None]:
    mie_exe = install_dir / "mie.exe"
    svc_exe = install_dir / "mie-service.exe"
    env = minimal_clean_env()

    ver = subprocess.run([str(mie_exe), "version"], capture_output=True, text=True, env=env, timeout=15)
    if ver.returncode != 0 or not ver.stdout.strip().startswith("mie "):
        return False, f"mie version failed (rc={ver.returncode}, out={ver.stdout!r}, err={ver.stderr!r})", None

    svc = subprocess.Popen(
        [str(svc_exe)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(install_dir),
    )
    ready = False
    for _ in range(80):
        ping = subprocess.run([str(mie_exe), "ping"], capture_output=True, text=True, env=env, timeout=10)
        if ping.returncode == 0:
            body = json.loads(ping.stdout.strip())
            if body.get("ok") is True and body.get("pong") is True:
                ready = True
                break
        if svc.poll() is not None:
            break
        time.sleep(0.1)

    if not ready:
        out_s = svc.stderr.read().decode("utf-8", "replace") if svc.stderr and svc.poll() is not None else ""
        if svc.poll() is None:
            svc.kill()
            svc.wait(timeout=10)
        return False, f"mie-service did not answer ping on default endpoint ({out_s})", None

    st = subprocess.run([str(mie_exe), "status"], capture_output=True, text=True, env=env, timeout=10)
    if st.returncode != 0:
        svc.kill()
        svc.wait(timeout=10)
        return False, f"mie status failed: rc={st.returncode} {st.stderr}", None
    st_body = json.loads(st.stdout.strip())
    if st_body.get("ok") is not True or st_body.get("engine") != "absent" or st_body.get("pid") != svc.pid:
        svc.kill()
        svc.wait(timeout=10)
        return False, f"unexpected status payload: {st_body} (expected pid={svc.pid})", None

    return True, f"mie version={ver.stdout.strip()!r}; mie-service(pid={svc.pid}) answered ping and status", svc


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Windows packaging acceptance tests P-1..P-9")
    parser.add_argument("--pkg-meta", default="build-pkg/out/windows-pkg-metadata.json")
    parser.add_argument("--stage-manifest", default="build-pkg/stage-manifest.json")
    args = parser.parse_args()

    pkg_meta = json.loads(Path(args.pkg_meta).read_text(encoding="utf-8"))
    stage_manifest = json.loads(Path(args.stage_manifest).read_text(encoding="utf-8"))
    installer_path = Path(pkg_meta["installer_path"]).resolve()
    stage_dir = Path(stage_manifest["stage_dir"]).resolve()
    version = pkg_meta["version"]
    short_sha = pkg_meta["short_sha"]

    install_dir = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "Dexmond MIE"
    start_menu_dir = (
        Path(os.environ["APPDATA"])
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Dexmond MIE"
    )
    user_data_dir = Path(os.environ["LOCALAPPDATA"]) / "DexmondMIE"

    # Clean any stale state before starting
    if install_dir.exists():
        shutil.rmtree(install_dir, ignore_errors=True)
    if user_data_dir.exists():
        shutil.rmtree(user_data_dir, ignore_errors=True)

    # ---- P-1 -------------------------------------------------------------------------
    actual_sha = sha256_file(installer_path)
    sha_txt = Path(pkg_meta["sha256_file"]).read_text(encoding="ascii").strip()
    name_ok = (
        installer_path.is_file()
        and version in installer_path.name
        and short_sha in installer_path.name
        and "UNSIGNED-TEST" in installer_path.name
        and actual_sha == pkg_meta["sha256"]
        and sha_txt.startswith(actual_sha)
    )
    record(
        "P-1",
        "PASS" if name_ok else "FAIL",
        f"installer={installer_path.name} sha256={actual_sha}",
    )

    # ---- P-2 -------------------------------------------------------------------------
    # Verify embedded Win32 manifest has asInvoker (no UAC elevation required)
    exe_bytes = installer_path.read_bytes()
    has_as_invoker = b'level="asInvoker"' in exe_bytes and b"requireAdministrator" not in exe_bytes

    # Probe standard-user token IsUserAnAdmin() == 0
    admin_probe_rc, used_safer_probe = run_as_standard_user(
        [
            sys.executable,
            "-c",
            "import ctypes, sys; sys.exit(0 if ctypes.windll.shell32.IsUserAnAdmin() == 0 else 9)",
        ]
    )

    baseline = snapshot_user_and_system_state()
    install_log = Path(os.environ["TEMP"]) / "dexmond-mie-p2-install.log"
    rc_install, used_safer = run_as_standard_user(
        [
            str(installer_path),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            f"/LOG={install_log}",
        ]
    )
    after_install = snapshot_user_and_system_state()

    expected_stage_rels = [entry["path"] for entry in stage_manifest["files"]]
    missing_installed = [
        rel for rel in expected_stage_rels if not (install_dir / Path(rel)).is_file()
    ]
    if not (install_dir / "unins000.exe").is_file():
        missing_installed.append("unins000.exe")
    if (install_dir / "mie-probe.exe").exists():
        missing_installed.append("UNEXPECTED:mie-probe.exe")

    expected_shortcuts = [
        start_menu_dir / "Start Dexmond MIE Background Service.lnk",
        start_menu_dir / "Dexmond MIE README.lnk",
        start_menu_dir / "Uninstall Dexmond MIE.lnk",
    ]
    missing_shortcuts = [str(s.name) for s in expected_shortcuts if not s.is_file()]

    added_files = after_install["files"] - baseline["files"]  # type: ignore[operator]
    install_prefix = os.path.normcase(str(install_dir))
    programs_parent = os.path.normcase(str(install_dir.parent))
    start_menu_prefix = os.path.normcase(str(start_menu_dir))

    stray_files = [
        p
        for p in sorted(added_files)
        if not (
            p == programs_parent
            or p == install_prefix
            or p.startswith(install_prefix + "\\")
            or p == start_menu_prefix
            or p.startswith(start_menu_prefix + "\\")
        )
    ]

    hkcu_run_added = {
        k: v
        for k, v in after_install["hkcu_run"].items()  # type: ignore[union-attr]
        if baseline["hkcu_run"].get(k) != v  # type: ignore[union-attr]
    }
    hklm_run_changed = after_install["hklm_run"] != baseline["hklm_run"]

    p2_ok = (
        has_as_invoker
        and (not used_safer_probe or admin_probe_rc == 0)
        and rc_install == 0
        and not missing_installed
        and not missing_shortcuts
        and not stray_files
        and set(hkcu_run_added.keys()) == {"Dexmond MIE"}
        and not hklm_run_changed
    )
    record(
        "P-2",
        "PASS" if p2_ok else "FAIL",
        f"rc={rc_install} non_elevated_safer={used_safer} asInvoker={has_as_invoker} "
        f"missing_files={missing_installed} missing_shortcuts={missing_shortcuts} "
        f"stray_files={stray_files} hkcu_run_added={hkcu_run_added}",
    )

    # ---- P-3 -------------------------------------------------------------------------
    dumpbin = find_dumpbin()
    deps_ok, deps_detail = check_dependents(dumpbin, install_dir)
    run_ok, run_detail, running_svc = start_and_verify_installed_programs(install_dir)
    record(
        "P-3",
        "PASS" if (deps_ok and run_ok) else "FAIL",
        f"{run_detail}; {deps_detail}",
    )

    # ---- P-4 (part 1: ticked default; part 2 tested after unticked reinstall) --------
    run_val = read_reg_values(winreg.HKEY_CURRENT_USER, RUN_KEY).get("Dexmond MIE", "")
    expected_run_target = os.path.normcase(f'"{install_dir / "mie-service.exe"}"')
    ticked_ok = os.path.normcase(run_val) == expected_run_target

    # ---- P-5 (choice 1: default KEEP user data folder while service is running!) -----
    user_data_dir.mkdir(parents=True, exist_ok=True)
    marker_file = user_data_dir / "state.json"
    marker_file.write_text('{"test_marker": true}\n', encoding="utf-8")

    # Ensure service is still actively running right before silent uninstall
    svc_was_running = running_svc is not None and running_svc.poll() is None
    unins_exe = install_dir / "unins000.exe"
    rc_unins_keep, _ = run_as_standard_user(
        [str(unins_exe), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    )
    wait_for_uninstall_finish(install_dir, start_menu_dir)
    if running_svc is not None:
        try:
            svc_exit_keep = running_svc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            running_svc.kill()
            svc_exit_keep = -999
    else:
        svc_exit_keep = -1

    after_unins_keep = snapshot_user_and_system_state()
    user_data_norm = os.path.normcase(str(user_data_dir))
    added_after_keep = {
        p
        for p in (after_unins_keep["files"] - baseline["files"])  # type: ignore[operator]
        if not (p == user_data_norm or p.startswith(user_data_norm + "\\"))
    }
    removed_after_keep = baseline["files"] - after_unins_keep["files"]  # type: ignore[operator]
    keep_choice_ok = (
        svc_was_running
        and rc_unins_keep == 0
        and svc_exit_keep == 0
        and marker_file.is_file()
        and not install_dir.exists()
        and not start_menu_dir.exists()
        and not reg_key_exists(winreg.HKEY_CURRENT_USER, APP_UNINSTALL_KEY)
        and "Dexmond MIE" not in after_unins_keep["hkcu_run"]
        and not running_mie_or_unins_processes()
        and not added_after_keep
        and not removed_after_keep
    )

    # ---- P-4 (part 2: unticked autostart choice) + P-6 (upgrade in place) ------------
    rc_unticked, _ = run_as_standard_user(
        [
            str(installer_path),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/MERGETASKS=!autostart",
        ]
    )
    unticked_absent = "Dexmond MIE" not in read_reg_values(winreg.HKEY_CURRENT_USER, RUN_KEY)
    p4_ok = ticked_ok and rc_unticked == 0 and unticked_absent
    record(
        "P-4",
        "PASS" if p4_ok else "FAIL",
        f"ticked_value={run_val!r}; unticked_absent={unticked_absent}",
    )

    # ---- P-6: Upgrade in place over existing (and running!) install ------------------
    upg_start_ok, _, upg_svc_before = start_and_verify_installed_programs(install_dir)
    rc_upgrade, _ = run_as_standard_user(
        [str(installer_path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
    )
    if upg_svc_before is not None:
        try:
            upg_old_exit = upg_svc_before.wait(timeout=5)
        except subprocess.TimeoutExpired:
            upg_svc_before.kill()
            upg_old_exit = -999
    else:
        upg_old_exit = -1

    unins_files = sorted(p.name for p in install_dir.glob("unins*.exe"))
    upg_after_ok, upg_detail, upg_svc_after = start_and_verify_installed_programs(install_dir)
    p6_ok = (
        upg_start_ok
        and rc_upgrade == 0
        and upg_old_exit == 0
        and unins_files == ["unins000.exe"]
        and upg_after_ok
    )
    record(
        "P-6",
        "PASS" if p6_ok else "FAIL",
        f"upgrade_rc={rc_upgrade} old_service_exit={upg_old_exit} uninstallers={unins_files}; {upg_detail}",
    )

    # ---- P-5 (choice 2: REMOVE user data folder while service is running!) -----------
    svc2_was_running = upg_svc_after is not None and upg_svc_after.poll() is None
    rc_unins_remove, _ = run_as_standard_user(
        [
            str(install_dir / "unins000.exe"),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/REMOVEUSERDATA=1",
        ]
    )
    wait_for_uninstall_finish(install_dir, start_menu_dir)
    if upg_svc_after is not None:
        try:
            svc_exit_remove = upg_svc_after.wait(timeout=5)
        except subprocess.TimeoutExpired:
            upg_svc_after.kill()
            svc_exit_remove = -999
    else:
        svc_exit_remove = -1

    after_unins_remove = snapshot_user_and_system_state()
    added_after_remove = after_unins_remove["files"] - baseline["files"]  # type: ignore[operator]
    removed_after_remove = baseline["files"] - after_unins_remove["files"]  # type: ignore[operator]
    remove_choice_ok = (
        svc2_was_running
        and rc_unins_remove == 0
        and svc_exit_remove == 0
        and not user_data_dir.exists()
        and not install_dir.exists()
        and not start_menu_dir.exists()
        and not reg_key_exists(winreg.HKEY_CURRENT_USER, APP_UNINSTALL_KEY)
        and "Dexmond MIE" not in after_unins_remove["hkcu_run"]
        and not running_mie_or_unins_processes()
        and not added_after_remove
        and not removed_after_remove
    )
    p5_ok = keep_choice_ok and remove_choice_ok
    record(
        "P-5",
        "PASS" if p5_ok else "FAIL",
        f"keep_choice_ok={keep_choice_ok} (svc_exit={svc_exit_keep}, extra={sorted(added_after_keep)}); "
        f"remove_choice_ok={remove_choice_ok} (svc_exit={svc_exit_remove}, extra={sorted(added_after_remove)})",
    )

    # ---- P-7 -------------------------------------------------------------------------
    p7_ok, p7_detail = check_licenses_and_notices(stage_dir)
    record("P-7", "PASS" if p7_ok else "FAIL", p7_detail)

    # ---- P-8 -------------------------------------------------------------------------
    wording_iss_text = Path(pkg_meta["wording_iss"]).read_text(encoding="utf-8")
    p8_ok, p8_detail = check_wording(
        "windows",
        stage_dir / "README.txt",
        extra_texts=[("wording.iss", wording_iss_text)],
    )
    # Verify exact autostart task sentence in wording.iss as well
    if "Start MIE's background service when I sign in" not in wording_iss_text:
        p8_ok = False
        p8_detail += "; autostart task wording missing from wording.iss"
    record("P-8", "PASS" if p8_ok else "FAIL", p8_detail)

    # ---- P-9 -------------------------------------------------------------------------
    build_log_text = Path(pkg_meta["log_file"]).read_text(encoding="utf-8")
    cert_env = os.environ.get("MIE_WIN_CODESIGN_CERT", "").strip()
    ts_env = os.environ.get("MIE_WIN_CODESIGN_TIMESTAMP_URL", "").strip()
    skip_logged = "SIGNING SKIPPED:" in build_log_text
    first_page_has_banner = (
        'MyWelcomeHeading "Welcome to Dexmond MIE Setup (UNSIGNED TEST BUILD)"' in wording_iss_text
        and "UNSIGNED TEST BUILD" in wording_iss_text
    )
    # Check WinVerifyTrust / Authenticode status on installer .exe -> NotSigned
    ps_sig = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-Command",
            f"(Get-AuthenticodeSignature -LiteralPath '{installer_path}').Status",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    created_keys = find_created_keys_or_signatures([Path("build-pkg")])
    p9_ok = (
        not cert_env
        and not ts_env
        and skip_logged
        and first_page_has_banner
        and ps_sig == "NotSigned"
        and not created_keys
    )
    record(
        "P-9",
        "PASS" if p9_ok else "FAIL",
        f"skip_logged={skip_logged} first_page_banner={first_page_has_banner} "
        f"authenticode_status={ps_sig} created_keys={created_keys}",
    )

    # ---- WITH_UI=ON status -----------------------------------------------------------
    record(
        "WITH_UI=ON",
        "NOT RUN",
        "mie-ui (Qt 6 window) is being developed on branch cpp/stage1-qt and is not present on cpp/stage1-pkg",
    )

    failed = [cid for cid, st, _ in results if st == "FAIL"]
    passed = [cid for cid, st, _ in results if st == "PASS"]
    not_run = [cid for cid, st, _ in results if st == "NOT RUN"]
    print(
        f"\nSUMMARY (Windows): {len(passed) + len(failed)} ran, "
        f"{len(passed)} passed, {len(failed)} failed, {len(not_run)} not run",
        flush=True,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
