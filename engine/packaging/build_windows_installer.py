#!/usr/bin/env python3
"""Build the Dexmond MIE per-user Windows installer using Inno Setup (ISCC.exe).

Reads the staged install tree manifest (`build-pkg/stage-manifest.json`) and
`engine/packaging/wording.json`, renders `wording.iss`, compiles
`engine/packaging/windows/mie.iss`, handles the code-signing placeholders
(`MIE_WIN_CODESIGN_CERT` and `MIE_WIN_CODESIGN_TIMESTAMP_URL`), and prints the
produced installer SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PACKAGING_DIR = Path(__file__).resolve().parent
WORDING_FILE = PACKAGING_DIR / "wording.json"
ISS_SCRIPT = PACKAGING_DIR / "windows" / "mie.iss"


def iss_quote(value: str) -> str:
    return value.replace('"', '""')


def iss_messages_escape(value: str) -> str:
    return value.replace("%", "%%")


def pascal_single_quote_escape(value: str) -> str:
    return value.replace("'", "''")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_iscc(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise RuntimeError(f"ISCC.exe not found at explicit path: {p}")
        return p
    which = shutil.which("ISCC.exe") or shutil.which("iscc")
    if which:
        return Path(which)
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Inno Setup 6"
        / "ISCC.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Inno Setup 6" / "ISCC.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c
    raise RuntimeError("ISCC.exe not found in PATH or standard Inno Setup 6 directories")


def sign_binary_if_configured(target: Path, cert: str, timestamp_url: str, log_lines: list[str]) -> None:
    signtool = shutil.which("signtool.exe")
    if not signtool:
        kits = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin"
        found = sorted(kits.glob("*/x64/signtool.exe"))
        if not found:
            raise RuntimeError("signtool.exe not found in PATH or Windows Kits")
        signtool = str(found[-1])

    cmd = [
        signtool,
        "sign",
        "/fd",
        "SHA256",
        "/td",
        "SHA256",
        "/tr",
        timestamp_url,
        "/f",
        cert,
        str(target),
    ]
    msg = f"Signing {target.name} with signtool.exe (timestamp {timestamp_url})"
    print(msg, flush=True)
    log_lines.append(msg)
    subprocess.run(cmd, check=True)


def render_wording_iss(
    wording: dict,
    manifest: dict,
    stage_dir: Path,
    out_dir: Path,
    base_filename: str,
    signed: bool,
) -> str:
    fs = wording["fixed_sentences"]
    win = wording["windows"]
    product = wording["product_name"]
    version = manifest["version"]

    if signed:
        ver_name = f"{product} {version}"
        comments = f"{product} {version} - {fs['what_it_does']}"
        welcome_heading = win["welcome_heading_signed"]
        welcome_paragraphs = [
            fs["what_it_does"],
            fs["account_boundary"],
            fs["no_scan_engine"],
        ]
    else:
        banner = wording["unsigned_banner"]
        ver_name = f"{product} {version} ({banner})"
        comments = f"{banner} - {fs['what_it_does']}"
        welcome_heading = win["welcome_heading_unsigned"]
        welcome_paragraphs = [
            wording["unsigned_notice"],
            fs["what_it_does"],
            fs["account_boundary"],
            fs["no_scan_engine"],
        ]

    welcome_body = "%n%n".join(iss_messages_escape(p) for p in welcome_paragraphs)
    uninstall_prompt_pascal = iss_quote(
        pascal_single_quote_escape(win["uninstall_userdata_prompt"])
    )

    defines = [
        f'#define MyAppName "{iss_quote(product)}"',
        f'#define MyAppPublisher "{iss_quote(wording["publisher"])}"',
        f'#define MyAppVersion "{iss_quote(version)}"',
        f'#define MyAppVerName "{iss_quote(ver_name)}"',
        f'#define MyAppComments "{iss_quote(comments)}"',
        f'#define MyStageDir "{iss_quote(str(stage_dir))}"',
        f'#define MyOutputDir "{iss_quote(str(out_dir))}"',
        f'#define MyOutputBaseFilename "{iss_quote(base_filename)}"',
        f'#define MyWithUI "{("1" if manifest["with_ui"] else "0")}"',
        f'#define MyIsSigned "{("1" if signed else "0")}"',
        f'#define MyWelcomeHeading "{iss_quote(iss_messages_escape(welcome_heading))}"',
        f'#define MyWelcomeBody "{iss_quote(welcome_body)}"',
        f'#define MyAutostartTask "{iss_quote(win["autostart_task"])}"',
        f'#define MyStartMenuUI "{iss_quote(win["start_menu_ui"])}"',
        f'#define MyStartMenuService "{iss_quote(win["start_menu_service"])}"',
        f'#define MyStartMenuReadme "{iss_quote(win["start_menu_readme"])}"',
        f'#define MyStartMenuUninstall "{iss_quote(win["start_menu_uninstall"])}"',
        f'#define MyUninstallPromptPascal "{uninstall_prompt_pascal}"',
    ]
    return "\n".join(defines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Dexmond MIE Windows Inno Setup installer")
    parser.add_argument("--manifest", default="build-pkg/stage-manifest.json")
    parser.add_argument("--out-dir", default="build-pkg/out")
    parser.add_argument("--work-dir", default="build-pkg/win-work")
    parser.add_argument("--log-file", default="build-pkg/windows-build.log")
    parser.add_argument("--iscc", default=None)
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    wording = json.loads(WORDING_FILE.read_text(encoding="utf-8"))
    stage_dir = Path(manifest["stage_dir"]).resolve()
    out_dir = Path(args.out_dir).resolve()
    work_dir = Path(args.work_dir).resolve()
    log_path = Path(args.log_file).resolve()

    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_lines: list[str] = []
    cert = os.environ.get("MIE_WIN_CODESIGN_CERT", "").strip()
    ts_url = os.environ.get("MIE_WIN_CODESIGN_TIMESTAMP_URL", "").strip()
    signed = bool(cert and ts_url)

    version = manifest["version"]
    short_sha = manifest["short_sha"]
    if signed:
        base_filename = f"Dexmond-MIE-Setup-{version}-{short_sha}-windows-x64"
        for exe_name in ("mie.exe", "mie-service.exe", "mie-worker.exe", "mie-ui.exe"):
            exe_path = stage_dir / exe_name
            if exe_path.is_file():
                sign_binary_if_configured(exe_path, cert, ts_url, log_lines)
    else:
        base_filename = (
            f"Dexmond-MIE-Setup-{version}-{short_sha}-windows-x64-UNSIGNED-TEST-BUILD"
        )
        skip_msg = (
            "SIGNING SKIPPED: MIE_WIN_CODESIGN_CERT and MIE_WIN_CODESIGN_TIMESTAMP_URL "
            "are empty; producing UNSIGNED TEST BUILD without signtool."
        )
        print(skip_msg, flush=True)
        log_lines.append(skip_msg)

    wording_iss_path = work_dir / "wording.iss"
    wording_iss_content = render_wording_iss(
        wording, manifest, stage_dir, out_dir, base_filename, signed
    )
    wording_iss_path.write_text(wording_iss_content, encoding="utf-8")

    iscc = find_iscc(args.iscc)
    iscc_sha256 = sha256_file(iscc)
    iscc_info = f"Using ISCC compiler: {iscc} (sha256={iscc_sha256})"
    print(iscc_info, flush=True)
    log_lines.append(iscc_info)

    cmd = [str(iscc), f"/I{work_dir}", str(ISS_SCRIPT)]
    print("Running:", " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    log_lines.append(proc.stdout)
    if proc.stderr:
        log_lines.append(proc.stderr)
    if proc.returncode != 0:
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        return proc.returncode

    installer_path = out_dir / f"{base_filename}.exe"
    if not installer_path.is_file():
        raise RuntimeError(f"Expected installer was not produced: {installer_path}")

    if signed:
        sign_binary_if_configured(installer_path, cert, ts_url, log_lines)

    digest = sha256_file(installer_path)
    sha_file = Path(f"{installer_path}.sha256")
    sha_file.write_text(f"{digest}  {installer_path.name}\n", encoding="ascii")

    summary_line = f"BUILT {installer_path.name} ({installer_path.stat().st_size} bytes) sha256={digest}"
    print(summary_line, flush=True)
    log_lines.append(summary_line)

    out_meta = {
        "installer_path": str(installer_path),
        "installer_name": installer_path.name,
        "sha256": digest,
        "sha256_file": str(sha_file),
        "wording_iss": str(wording_iss_path),
        "log_file": str(log_path),
        "version": version,
        "commit": manifest["commit"],
        "short_sha": short_sha,
        "signed": signed,
    }
    (out_dir / "windows-pkg-metadata.json").write_text(
        json.dumps(out_meta, indent=2) + "\n", encoding="utf-8"
    )
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
