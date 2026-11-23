#!/usr/bin/env python3
"""Build Dexmond MIE Linux packages (.deb and .tar.gz) plus SHA256SUMS.

Layout of `.deb`:
  - `/opt/dexmond-mie/` (programs `mie`, `mie-service`, non-root helper
    `mie-autostart`, `README.txt`, `licenses/...`, and optional `lib/` + `plugins/`
    when `WITH_UI=ON`)
  - `/usr/bin/mie` (`#!/bin/sh` wrapper around `/opt/dexmond-mie/mie`)
  - `/etc/xdg/autostart/dexmond-mie-service.desktop` (starts `mie-service` per
    user at desktop sign-in via `mie-autostart`, which exits immediately if UID=0)
  - `DEBIAN/postrm` cleans `/opt/dexmond-mie` and `/etc/xdg/autostart/dexmond-mie-service.desktop`
    on `purge`, leaving user data in `$HOME` untouched.

Handles `MIE_LINUX_GPG_KEY_ID` signing placeholder: when empty, marks `.deb`
Description with `UNSIGNED TEST BUILD`, names packages with `UNSIGNED-TEST-BUILD`,
and logs that GPG signing of `SHA256SUMS` was skipped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path

PACKAGING_DIR = Path(__file__).resolve().parent
WORDING_FILE = PACKAGING_DIR / "wording.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_tar_gz(
    stage_dir: Path, out_dir: Path, archive_stem: str
) -> Path:
    tar_path = out_dir / f"{archive_stem}.tar.gz"
    exec_names = {"mie", "mie-service", "mie-ui"}

    def reset_tarinfo(ti: tarfile.TarInfo) -> tarfile.TarInfo:
        ti.uid = 0
        ti.gid = 0
        ti.uname = "root"
        ti.gname = "root"
        ti.mtime = 1700000000
        if ti.isdir():
            ti.mode = 0o755
        else:
            name = os.path.basename(ti.name)
            if name in exec_names or name.endswith(".so") or ".so." in name:
                ti.mode = 0o755
            else:
                ti.mode = 0o644
        return ti

    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(stage_dir, arcname=archive_stem, filter=reset_tarinfo)
    return tar_path


def compute_shlibs_depends(binaries: list[Path], work_dir: Path) -> str:
    shlib_work = work_dir / "shlibdeps"
    if shlib_work.exists():
        shutil.rmtree(shlib_work)
    (shlib_work / "debian").mkdir(parents=True)
    (shlib_work / "debian" / "control").write_text(
        "Source: dexmond-mie\n\nPackage: dexmond-mie\nArchitecture: amd64\nDescription: temp\n",
        encoding="utf-8",
    )
    cmd = ["dpkg-shlibdeps", "-O", *[str(b) for b in binaries]]
    out = subprocess.run(
        cmd, cwd=str(shlib_work), check=True, capture_output=True, text=True
    )
    for line in out.stdout.splitlines():
        if line.startswith("shlibs:Depends="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError(f"dpkg-shlibdeps did not output shlibs:Depends: {out.stdout} {out.stderr}")


def format_deb_description(wording: dict, signed: bool) -> str:
    fs = wording["fixed_sentences"]
    lin = wording["linux"]
    synopsis = lin["deb_synopsis_signed"] if signed else lin["deb_synopsis_unsigned"]

    paragraphs: list[str] = []
    if not signed:
        paragraphs.append(wording["unsigned_notice"])
    paragraphs.extend(
        [
            fs["what_it_does"],
            fs["account_boundary"],
            fs["linux_scope"],
            fs["no_scan_engine"],
        ]
    )

    body_lines: list[str] = []
    for idx, para in enumerate(paragraphs):
        if idx > 0:
            body_lines.append(" .")
        for wrapped in textwrap.wrap(para, width=76, break_long_words=False, break_on_hyphens=False):
            body_lines.append(f" {wrapped}")

    return synopsis + "\n" + "\n".join(body_lines)


def set_clean_permissions(deb_root: Path) -> None:
    exec_rel_paths = {
        "opt/dexmond-mie/mie",
        "opt/dexmond-mie/mie-service",
        "opt/dexmond-mie/mie-ui",
        "opt/dexmond-mie/mie-autostart",
        "usr/bin/mie",
        "usr/bin/mie-ui",
        "DEBIAN/postrm",
    }
    for p in [deb_root, *deb_root.rglob("*")]:
        if p.is_symlink():
            continue
        if p.is_dir():
            os.chmod(p, 0o755)
        else:
            rel = p.relative_to(deb_root).as_posix()
            if rel in exec_rel_paths or rel.endswith(".so") or ".so." in rel:
                os.chmod(p, 0o755)
            else:
                os.chmod(p, 0o644)


def build_deb(
    stage_dir: Path,
    out_dir: Path,
    work_dir: Path,
    wording: dict,
    version: str,
    short_sha: str,
    signed: bool,
    with_ui: bool,
) -> Path:
    deb_root = work_dir / "deb-root"
    if deb_root.exists():
        shutil.rmtree(deb_root)

    opt_dir = deb_root / "opt" / "dexmond-mie"
    usr_bin = deb_root / "usr" / "bin"
    autostart_dir = deb_root / "etc" / "xdg" / "autostart"
    debian_dir = deb_root / "DEBIAN"

    shutil.copytree(stage_dir, opt_dir)
    usr_bin.mkdir(parents=True, exist_ok=True)
    autostart_dir.mkdir(parents=True, exist_ok=True)
    debian_dir.mkdir(parents=True, exist_ok=True)

    # Non-root XDG autostart helper inside /opt/dexmond-mie/
    autostart_helper = opt_dir / "mie-autostart"
    autostart_helper.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "$(id -u)" -eq 0 ]; then\n'
        "    exit 0\n"
        "fi\n"
        "exec /opt/dexmond-mie/mie-service\n",
        encoding="utf-8",
    )

    # /usr/bin/mie command-line wrapper
    mie_wrapper = usr_bin / "mie"
    mie_wrapper.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'exec /opt/dexmond-mie/mie "$@"\n',
        encoding="utf-8",
    )
    if with_ui and (opt_dir / "mie-ui").is_file():
        (usr_bin / "mie-ui").write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'exec /opt/dexmond-mie/mie-ui "$@"\n',
            encoding="utf-8",
        )

    # /etc/xdg/autostart/dexmond-mie-service.desktop
    desktop_file = autostart_dir / "dexmond-mie-service.desktop"
    desktop_file.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Version=1.0\n"
        f"Name={wording['linux']['desktop_name']}\n"
        f"Comment={wording['fixed_sentences']['what_it_does']}\n"
        "Exec=/opt/dexmond-mie/mie-autostart\n"
        "TryExec=/opt/dexmond-mie/mie-service\n"
        "Terminal=false\n"
        "NoDisplay=true\n"
        "StartupNotify=false\n"
        "X-GNOME-Autostart-enabled=true\n",
        encoding="utf-8",
    )

    elf_binaries = [opt_dir / "mie", opt_dir / "mie-service"]
    if with_ui and (opt_dir / "mie-ui").is_file():
        elf_binaries.append(opt_dir / "mie-ui")
    depends = compute_shlibs_depends(elf_binaries, work_dir)

    total_bytes = sum(
        p.stat().st_size
        for p in deb_root.rglob("*")
        if p.is_file() and "DEBIAN" not in p.parts
    )
    installed_kib = max(1, math.ceil(total_bytes / 1024))

    deb_version = f"{version}+git{short_sha}"
    description = format_deb_description(wording, signed)
    control_text = (
        "Package: dexmond-mie\n"
        f"Version: {deb_version}\n"
        "Section: utils\n"
        "Priority: optional\n"
        "Architecture: amd64\n"
        f"Installed-Size: {installed_kib}\n"
        f"Depends: {depends}\n"
        "Maintainer: Dexmond Engineering <support@dexmond.com>\n"
        f"Description: {description}\n"
    )
    (debian_dir / "control").write_text(control_text, encoding="utf-8")
    (debian_dir / "conffiles").write_text(
        "/etc/xdg/autostart/dexmond-mie-service.desktop\n", encoding="utf-8"
    )

    md5_lines: list[str] = []
    for p in sorted(deb_root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(deb_root).as_posix()
        if rel.startswith("DEBIAN/") or rel.startswith("etc/"):
            continue
        md5_lines.append(f"{md5_file(p)}  {rel}")
    (debian_dir / "md5sums").write_text("\n".join(md5_lines) + "\n", encoding="utf-8")

    (debian_dir / "postrm").write_text(
        "#!/bin/sh\n"
        "set -e\n"
        'if [ "$1" = "purge" ]; then\n'
        "    rm -f /etc/xdg/autostart/dexmond-mie-service.desktop\n"
        "    rm -rf /opt/dexmond-mie\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )

    set_clean_permissions(deb_root)

    label = "" if signed else "_UNSIGNED-TEST-BUILD"
    deb_name = f"dexmond-mie_{deb_version}_amd64{label}.deb"
    deb_path = out_dir / deb_name
    subprocess.run(
        ["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(deb_root), str(deb_path)],
        check=True,
    )
    return deb_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Dexmond MIE Linux .deb and .tar.gz")
    parser.add_argument("--manifest", default="build-pkg/stage-manifest.json")
    parser.add_argument("--out-dir", default="build-pkg/out")
    parser.add_argument("--work-dir", default="build-pkg/linux-work")
    parser.add_argument("--log-file", default="build-pkg/linux-build.log")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    wording = json.loads(WORDING_FILE.read_text(encoding="utf-8"))
    stage_dir = Path(manifest["stage_dir"]).resolve()
    out_dir = Path(args.out_dir).resolve()
    work_dir = Path(args.work_dir).resolve()
    log_path = Path(args.log_file).resolve()

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_lines: list[str] = []
    gpg_key_id = os.environ.get("MIE_LINUX_GPG_KEY_ID", "").strip()
    signed = bool(gpg_key_id)
    version = manifest["version"]
    short_sha = manifest["short_sha"]
    with_ui = bool(manifest["with_ui"])

    tar_stem = (
        f"dexmond-mie-{version}-{short_sha}-linux-x64"
        if signed
        else f"dexmond-mie-{version}-{short_sha}-linux-x64-UNSIGNED-TEST-BUILD"
    )
    tar_path = build_tar_gz(stage_dir, out_dir, tar_stem)
    deb_path = build_deb(
        stage_dir, out_dir, work_dir, wording, version, short_sha, signed, with_ui
    )

    packages = [deb_path, tar_path]
    sha_lines: list[str] = []
    for pkg in packages:
        digest = sha256_file(pkg)
        line = f"{digest}  {pkg.name}"
        sha_lines.append(line)
        print(f"BUILT {pkg.name} ({pkg.stat().st_size} bytes) sha256={digest}", flush=True)
        log_lines.append(line)

    sha256sums_path = out_dir / "SHA256SUMS"
    sha256sums_path.write_text("\n".join(sha_lines) + "\n", encoding="ascii")

    if signed:
        sig_path = out_dir / "SHA256SUMS.asc"
        msg = f"Signing SHA256SUMS with GPG key MIE_LINUX_GPG_KEY_ID={gpg_key_id}"
        print(msg, flush=True)
        log_lines.append(msg)
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--local-user",
                gpg_key_id,
                "--armor",
                "--detach-sign",
                "--output",
                str(sig_path),
                str(sha256sums_path),
            ],
            check=True,
        )
    else:
        skip_msg = (
            "SIGNING SKIPPED: MIE_LINUX_GPG_KEY_ID is empty; SHA256SUMS is unsigned "
            "(UNSIGNED TEST BUILD)."
        )
        print(skip_msg, flush=True)
        log_lines.append(skip_msg)

    meta = {
        "deb_path": str(deb_path),
        "deb_name": deb_path.name,
        "tar_path": str(tar_path),
        "tar_name": tar_path.name,
        "sha256sums_path": str(sha256sums_path),
        "log_file": str(log_path),
        "version": version,
        "commit": manifest["commit"],
        "short_sha": short_sha,
        "signed": signed,
    }
    (out_dir / "linux-pkg-metadata.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
