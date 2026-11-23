#!/usr/bin/env python3
"""Linux packaging acceptance tests (L-1 through L-8, plus Debian 13 container mode).

Modes:
  - Default (`ubuntu-latest` host): runs L-1 through L-8 and reports `WITH_UI=ON`
    as `NOT RUN`.
  - `--debian-container <deb_path>`: runs inside a `debian:13` container to verify
    the built `.deb` installs (`dpkg -i`), runs as a non-root user, never starts
    for root, and purges cleanly (`dpkg --purge`) on Debian 13 as well.
  - `--user-smoke <mie_bin> <service_bin>`: internal helper invoked as a non-root
    user to verify `mie version`, `mie-service` default-endpoint `ping`/`status`,
    Unix-only socket check, `ldd`, and `mie shutdown`.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from common_checks import (
    REPO_ROOT,
    check_licenses_and_notices,
    check_wording,
    find_created_keys_or_signatures,
)

results: list[tuple[str, str, str]] = []


def record(case_id: str, status: str, detail: str) -> None:
    assert status in ("PASS", "FAIL", "NOT RUN")
    print(f"{status}  {case_id}: {detail}", flush=True)
    results.append((case_id, status, detail))


def non_unix_sockets_of(pid: int) -> tuple[int, int]:
    """Return `(total_sockets, non_unix_sockets)` held by `pid`."""
    fd_dir = f"/proc/{pid}/fd"
    inodes: set[str] = set()
    for fd in os.listdir(fd_dir):
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[len("socket:[") : -1])
    if not inodes:
        return 0, 0
    unix_inodes: set[str] = set()
    with open("/proc/net/unix", encoding="utf-8") as f:
        next(f, None)
        for line in f:
            parts = line.split()
            if len(parts) >= 7:
                unix_inodes.add(parts[6])
    non_unix = sum(1 for ino in inodes if ino not in unix_inodes)
    return len(inodes), non_unix


def check_ldd_no_missing(binaries: list[Path]) -> tuple[bool, str]:
    missing: list[str] = []
    for b in binaries:
        out = subprocess.run(
            ["ldd", str(b)], check=True, capture_output=True, text=True
        )
        for line in out.stdout.splitlines():
            if "not found" in line:
                missing.append(f"{b}: {line.strip()}")
    if missing:
        return False, "; ".join(missing)
    return True, f"ldd clean for {[b.name for b in binaries]}"


def run_normal_user_smoke(
    mie_bin: Path, svc_bin: Path, elf_bins: list[Path] | None = None
) -> tuple[bool, str]:
    if os.geteuid() == 0:
        return False, "refusing to run normal-user smoke check as root (UID 0)"

    if elf_bins is None:
        if mie_bin == Path("/usr/bin/mie") and Path("/opt/dexmond-mie/mie").is_file():
            elf_bins = [Path("/opt/dexmond-mie/mie"), svc_bin]
        else:
            elf_bins = [mie_bin, svc_bin]

    ldd_ok, ldd_detail = check_ldd_no_missing(elf_bins)
    if not ldd_ok:
        return False, ldd_detail

    ver = subprocess.run([str(mie_bin), "version"], capture_output=True, text=True, timeout=15)
    if ver.returncode != 0 or not ver.stdout.strip().startswith("mie "):
        return False, f"mie version failed: rc={ver.returncode} out={ver.stdout!r} err={ver.stderr!r}"

    svc = subprocess.Popen(
        [str(svc_bin)], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        ready = False
        for _ in range(80):
            ping = subprocess.run([str(mie_bin), "ping"], capture_output=True, text=True, timeout=10)
            if ping.returncode == 0:
                body = json.loads(ping.stdout.strip())
                if body.get("ok") is True and body.get("pong") is True:
                    ready = True
                    break
            if svc.poll() is not None:
                break
            time.sleep(0.1)
        if not ready:
            err_s = svc.stderr.read().decode("utf-8", "replace") if svc.stderr and svc.poll() is not None else ""
            return False, f"mie-service failed to answer ping on default endpoint ({err_s})"

        st = subprocess.run([str(mie_bin), "status"], capture_output=True, text=True, timeout=10)
        if st.returncode != 0:
            return False, f"mie status failed: rc={st.returncode} err={st.stderr}"
        st_body = json.loads(st.stdout.strip())
        if st_body.get("ok") is not True or st_body.get("engine") != "absent" or st_body.get("pid") != svc.pid:
            return False, f"unexpected status body: {st_body}"

        total_sock, non_unix = non_unix_sockets_of(svc.pid)
        if total_sock < 1 or non_unix != 0:
            return False, f"socket check failed: total_sockets={total_sock}, non_unix_sockets={non_unix}"

        shut = subprocess.run([str(mie_bin), "shutdown"], capture_output=True, text=True, timeout=10)
        if shut.returncode != 0:
            return False, f"mie shutdown failed: rc={shut.returncode}"
        exit_rc = svc.wait(timeout=15)
        if exit_rc != 0:
            return False, f"mie-service exited with {exit_rc} after shutdown"
    finally:
        if svc.poll() is None:
            svc.kill()
            svc.wait(timeout=10)

    return (
        True,
        f"uid={os.geteuid()} {ver.stdout.strip()!r}, ping/status ok, "
        f"sockets=(unix={total_sock}, non_unix={non_unix}), {ldd_detail}",
    )


def snapshot_system_tree() -> set[str]:
    """Snapshot filesystem paths outside ephemeral/virtual/workspace mounts."""
    prune_Exact = {
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/var/tmp",
        "/var/cache",
        "/var/log",
        "/home",
        "/mnt",
        "/media",
        "/work",
        "/mie-src",
        str(REPO_ROOT),
    }
    paths: set[str] = set()
    for root, dirs, files in os.walk("/", followlinks=False):
        dirs[:] = [
            d
            for d in dirs
            if os.path.join(root, d) not in prune_Exact
        ]
        for d in dirs:
            paths.add(os.path.join(root, d))
        for f in files:
            paths.add(os.path.join(root, f))
    return paths


def is_dpkg_db_path(p: str) -> bool:
    return p == "/var/lib/dpkg" or p.startswith("/var/lib/dpkg/")


def run_root_cmd(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    if os.geteuid() == 0:
        return subprocess.run(cmd, check=True, capture_output=True, text=True)
    return subprocess.run(["sudo", "-n", *cmd], check=True, capture_output=True, text=True)


def verify_deb_lifecycle(deb_path: Path, prefix: str = "") -> None:
    tag = lambda code: f"{prefix}{code}" if prefix else code

    expected_files_modes = {
        "/opt/dexmond-mie/mie": 0o755,
        "/opt/dexmond-mie/mie-service": 0o755,
        "/opt/dexmond-mie/mie-autostart": 0o755,
        "/opt/dexmond-mie/README.txt": 0o644,
        "/opt/dexmond-mie/licenses/openssl-LICENSE.txt": 0o644,
        "/opt/dexmond-mie/licenses/nlohmann-json-LICENSE.txt": 0o644,
        "/opt/dexmond-mie/licenses/THIRD-PARTY-NOTICES.txt": 0o644,
        "/usr/bin/mie": 0o755,
        "/etc/xdg/autostart/dexmond-mie-service.desktop": 0o644,
    }

    before = snapshot_system_tree()
    run_root_cmd(["dpkg", "-i", str(deb_path)])
    after_install = snapshot_system_tree()

    # ---- L-3 -------------------------------------------------------------------------
    l3_errors: list[str] = []
    for fpath, exp_mode in expected_files_modes.items():
        if not os.path.lexists(fpath):
            l3_errors.append(f"missing {fpath}")
            continue
        st = os.lstat(fpath)
        if st.st_uid != 0 or st.st_gid != 0:
            l3_errors.append(f"{fpath} owner is {st.st_uid}:{st.st_gid}, expected 0:0")
        mode = stat.S_IMODE(st.st_mode)
        if mode != exp_mode:
            l3_errors.append(f"{fpath} mode is {oct(mode)}, expected {oct(exp_mode)}")
        if mode & 0o6000:
            l3_errors.append(f"{fpath} has setuid/setgid bit ({oct(mode)})")

    for root_str, dirs, files in os.walk("/opt/dexmond-mie"):
        for item in [*dirs, *files]:
            full = os.path.join(root_str, item)
            st = os.lstat(full)
            if stat.S_IMODE(st.st_mode) & 0o6000:
                l3_errors.append(f"setuid/setgid found on {full}")

    added = after_install - before
    allowed_outside_dpkg = {
        "/opt",
        "/opt/dexmond-mie",
        "/usr/bin/mie",
        "/etc/xdg",
        "/etc/xdg/autostart",
        "/etc/xdg/autostart/dexmond-mie-service.desktop",
    }
    stray = [
        p
        for p in sorted(added)
        if not (
            is_dpkg_db_path(p)
            or p in allowed_outside_dpkg
            or p.startswith("/opt/dexmond-mie/")
        )
    ]
    if stray:
        l3_errors.append(f"files outside permitted paths: {stray}")

    record(
        tag("L-3"),
        "PASS" if not l3_errors else "FAIL",
        "all expected files present with root:root and expected modes, no setuid, no stray files"
        if not l3_errors
        else "; ".join(l3_errors),
    )

    # ---- L-4 -------------------------------------------------------------------------
    if os.geteuid() != 0:
        l4_ok, l4_detail = run_normal_user_smoke(
            Path("/usr/bin/mie"), Path("/opt/dexmond-mie/mie-service")
        )
        home_data_dir = Path.home() / ".local" / "share" / "dexmond-mie"
    else:
        pw = pwd.getpwnam("mieuser")
        runtime_dir = Path(f"/run/user/{pw.pw_uid}")
        runtime_dir.mkdir(parents=True, exist_ok=True)
        os.chown(runtime_dir, pw.pw_uid, pw.pw_gid)
        os.chmod(runtime_dir, 0o700)
        home_data_dir = Path(pw.pw_dir) / ".local" / "share" / "dexmond-mie"

        def drop_privs() -> None:
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)

        sub_env = {
            "HOME": pw.pw_dir,
            "USER": "mieuser",
            "LOGNAME": "mieuser",
            "XDG_RUNTIME_DIR": str(runtime_dir),
            "PATH": "/usr/bin:/bin",
        }
        sub = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--user-smoke",
                "/usr/bin/mie",
                "/opt/dexmond-mie/mie-service",
            ],
            preexec_fn=drop_privs,
            env=sub_env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        l4_ok = sub.returncode == 0
        l4_detail = (sub.stdout.strip() + " " + sub.stderr.strip()).strip()

    record(tag("L-4"), "PASS" if l4_ok else "FAIL", l4_detail)

    # ---- L-5 -------------------------------------------------------------------------
    l5_errors: list[str] = []
    # Check no mie-service runs as root
    for pid_entry in os.listdir("/proc"):
        if not pid_entry.isdigit():
            continue
        try:
            exe = os.path.basename(os.readlink(f"/proc/{pid_entry}/exe"))
            st_proc = os.stat(f"/proc/{pid_entry}")
            if exe == "mie-service" and st_proc.st_uid == 0:
                l5_errors.append(f"mie-service running as root (pid={pid_entry})")
        except OSError:
            continue

    # Verify /opt/dexmond-mie/mie-autostart invoked as root exits 0 immediately without starting mie-service
    run_root_cmd(["/opt/dexmond-mie/mie-autostart"])
    if Path("/root/.cache/dexmond-mie/service.sock").exists():
        l5_errors.append("mie-autostart created root socket when invoked as root")

    # Check no system service unit installed anywhere
    for sys_svc_dir in (
        Path("/etc/systemd/system"),
        Path("/lib/systemd/system"),
        Path("/usr/lib/systemd/system"),
        Path("/etc/init.d"),
    ):
        if sys_svc_dir.is_dir():
            matches = [
                str(p)
                for p in sys_svc_dir.rglob("*")
                if "dexmond" in p.name.lower() or p.name.lower().startswith("mie")
            ]
            if matches:
                l5_errors.append(f"system service files found: {matches}")

    record(
        tag("L-5"),
        "PASS" if not l5_errors else "FAIL",
        "no root mie-service running, mie-autostart refuses UID 0, no system service installed"
        if not l5_errors
        else "; ".join(l5_errors),
    )

    # ---- L-6 -------------------------------------------------------------------------
    home_data_dir.mkdir(parents=True, exist_ok=True)
    home_marker = home_data_dir / "user-keep.json"
    home_marker.write_text('{"keep": true}\n', encoding="utf-8")

    run_root_cmd(["dpkg", "--purge", "dexmond-mie"])
    after_purge = snapshot_system_tree()

    leftover_outside_dpkg = [
        p for p in sorted(after_purge - before) if not is_dpkg_db_path(p)
    ]
    dpkg_info_leftovers = sorted(str(p) for p in Path("/var/lib/dpkg/info").glob("dexmond-mie*"))
    pkg_query = subprocess.run(
        ["dpkg-query", "-W", "dexmond-mie"], capture_output=True, text=True
    )
    home_kept = home_marker.is_file()
    shutil.rmtree(home_data_dir, ignore_errors=True)

    l6_ok = (
        not leftover_outside_dpkg
        and not dpkg_info_leftovers
        and pkg_query.returncode != 0
        and home_kept
    )
    record(
        tag("L-6"),
        "PASS" if l6_ok else "FAIL",
        f"leftovers={leftover_outside_dpkg} dpkg_info={dpkg_info_leftovers} home_userdata_untouched={home_kept}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Linux packaging acceptance tests L-1..L-8")
    parser.add_argument("--pkg-meta", default="build-pkg/out/linux-pkg-metadata.json")
    parser.add_argument("--stage-manifest", default="build-pkg/stage-manifest.json")
    parser.add_argument("--debian-container", default=None, help="Path to .deb for Debian 13 container checks")
    parser.add_argument("--user-smoke", nargs=2, default=None, metavar=("MIE", "SERVICE"))
    args = parser.parse_args()

    if args.user_smoke:
        ok, detail = run_normal_user_smoke(Path(args.user_smoke[0]), Path(args.user_smoke[1]))
        print(detail)
        return 0 if ok else 1

    if args.debian_container:
        verify_deb_lifecycle(Path(args.debian_container).resolve(), prefix="debian13:")
        failed = [cid for cid, st, _ in results if st == "FAIL"]
        return 1 if failed else 0

    pkg_meta = json.loads(Path(args.pkg_meta).read_text(encoding="utf-8"))
    stage_manifest = json.loads(Path(args.stage_manifest).read_text(encoding="utf-8"))
    deb_path = Path(pkg_meta["deb_path"]).resolve()
    tar_path = Path(pkg_meta["tar_path"]).resolve()
    sha256sums_path = Path(pkg_meta["sha256sums_path"]).resolve()
    stage_dir = Path(stage_manifest["stage_dir"]).resolve()
    version = pkg_meta["version"]
    short_sha = pkg_meta["short_sha"]

    # ---- L-1 -------------------------------------------------------------------------
    chk_sha = subprocess.run(
        ["sha256sum", "-c", sha256sums_path.name],
        cwd=str(sha256sums_path.parent),
        capture_output=True,
        text=True,
    )
    l1_ok = (
        deb_path.is_file()
        and tar_path.is_file()
        and version in deb_path.name
        and short_sha in deb_path.name
        and "UNSIGNED-TEST" in deb_path.name
        and version in tar_path.name
        and short_sha in tar_path.name
        and "UNSIGNED-TEST" in tar_path.name
        and chk_sha.returncode == 0
    )
    record(
        "L-1",
        "PASS" if l1_ok else "FAIL",
        f"deb={deb_path.name}, tar={tar_path.name}; sha256sum: {chk_sha.stdout.strip().replace(chr(10), '; ')}",
    )

    # ---- L-2 -------------------------------------------------------------------------
    # First print full raw lintian output to the CI log for complete auditability.
    raw_lintian = subprocess.run(
        ["lintian", "--tag-display-limit", "0", str(deb_path)],
        capture_output=True,
        text=True,
    )
    print("--- lintian raw output ---", flush=True)
    if raw_lintian.stdout:
        print(raw_lintian.stdout.rstrip(), flush=True)
    if raw_lintian.stderr:
        print(raw_lintian.stderr.rstrip(), flush=True)
    print("--- end lintian raw output ---", flush=True)

    # Suppress ONLY the three Debian-archive-only tags directly caused by the brief's
    # layout rules (/opt/dexmond-mie/ in Req 4, and no /usr/share/doc in L-3).
    lintian_res = subprocess.run(
        [
            "lintian",
            "--tag-display-limit",
            "0",
            "--suppress-tags",
            "dir-or-file-in-opt,no-copyright-file,no-changelog",
            str(deb_path),
        ],
        capture_output=True,
        text=True,
    )
    errors_lines = [
        ln for ln in lintian_res.stdout.splitlines() if ln.startswith("E:")
    ]
    warnings_lines = [
        ln for ln in lintian_res.stdout.splitlines() if ln.startswith("W:")
    ]
    l2_ok = lintian_res.returncode == 0 and not errors_lines
    record(
        "L-2",
        "PASS" if l2_ok else "FAIL",
        f"errors={len(errors_lines)} warnings={len(warnings_lines)} ({warnings_lines})",
    )

    # ---- L-3, L-4, L-5, L-6 on ubuntu-latest -----------------------------------------
    verify_deb_lifecycle(deb_path)

    # ---- L-7 -------------------------------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="mie-tar-l7-") as tmp:
        with tarfile.open(tar_path, "r:gz") as tf:
            tf.extractall(tmp, filter="data")
        roots = [p for p in Path(tmp).iterdir() if p.is_dir()]
        if len(roots) != 1:
            record("L-7", "FAIL", f"expected 1 top directory in tar.gz, got {roots}")
        else:
            unpacked = roots[0]
            l7_ok, l7_detail = run_normal_user_smoke(
                unpacked / "mie", unpacked / "mie-service"
            )
            record("L-7", "PASS" if l7_ok else "FAIL", f"unpacked={unpacked.name}: {l7_detail}")

    # ---- L-8 -------------------------------------------------------------------------
    lic_ok, lic_detail = check_licenses_and_notices(stage_dir)
    deb_desc = subprocess.run(
        ["dpkg-deb", "-f", str(deb_path), "Description"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    word_ok, word_detail = check_wording(
        "linux",
        stage_dir / "README.txt",
        debian_control_description=deb_desc,
    )
    build_log_text = Path(pkg_meta["log_file"]).read_text(encoding="utf-8")
    gpg_env = os.environ.get("MIE_LINUX_GPG_KEY_ID", "").strip()
    skip_logged = "SIGNING SKIPPED:" in build_log_text
    desc_has_banner = "UNSIGNED TEST BUILD" in deb_desc
    created_keys = find_created_keys_or_signatures([Path("build-pkg")])
    sign_ok = (not gpg_env) and skip_logged and desc_has_banner and (not created_keys)

    l8_ok = lic_ok and word_ok and sign_ok
    record(
        "L-8",
        "PASS" if l8_ok else "FAIL",
        f"licences={lic_ok} ({lic_detail}); wording={word_ok} ({word_detail}); "
        f"signing_skip={sign_ok} (banner_in_desc={desc_has_banner}, created_keys={created_keys})",
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
        f"\nSUMMARY (Ubuntu): {len(passed) + len(failed)} ran, "
        f"{len(passed)} passed, {len(failed)} failed, {len(not_run)} not run",
        flush=True,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
