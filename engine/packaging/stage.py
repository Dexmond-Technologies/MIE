#!/usr/bin/env python3
"""Shared staging script for Dexmond MIE (Windows and Linux).

Builds the C++ engine from the read-only `engine/` sources using the pinned vcpkg
commit from `engine/third_party/pins.json` and lays out one clean staging directory:
  - `mie-service` and `mie` (never `mie-probe` and no test binaries)
  - every non-system shared library required by those programs (plus app-local
    MSVC C++ runtime DLLs on Windows), each as its own separate file
  - `licenses/` containing the upstream licence texts from the pinned vcpkg build
    and `THIRD-PARTY-NOTICES.txt` generated from `engine/third_party/pins.json`
  - `README.txt` rendered from `engine/packaging/wording.json`

Supports `--with-ui` / `WITH_UI=ON` (default OFF): when ON, also stages `mie-ui`,
Qt 6 Core/Gui/Widgets and the platform plugin as separate, replaceable shared
library files, plus `LGPL-3.0.txt`, `GPL-3.0.txt`, `QT-LGPL-NOTICE.txt`, and
`QT-SOURCE-OFFER.txt`.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from common_checks import check_worker_and_no_forbidden_programs

PACKAGING_DIR = Path(__file__).resolve().parent
ENGINE_DIR = PACKAGING_DIR.parent
REPO_ROOT = ENGINE_DIR.parent
CMAKE_FILE = ENGINE_DIR / "CMakeLists.txt"
PINS_FILE = ENGINE_DIR / "third_party" / "pins.json"
WORDING_FILE = PACKAGING_DIR / "wording.json"
LEGAL_DIR = PACKAGING_DIR / "legal"


def parse_bool_flag(value: str) -> bool:
    v = value.strip().upper()
    if v in ("1", "ON", "TRUE", "YES"):
        return True
    if v in ("0", "OFF", "FALSE", "NO", ""):
        return False
    raise argparse.ArgumentTypeError(f"Expected ON/OFF boolean value, got {value!r}")


def read_project_version() -> str:
    text = CMAKE_FILE.read_text(encoding="utf-8")
    m = re.search(
        r"project\s*\(\s*mie_engine\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)",
        text,
    )
    if not m:
        raise RuntimeError(f"Could not parse mie_engine VERSION from {CMAKE_FILE}")
    return m.group(1)


def resolve_commit(explicit: str | None) -> str:
    if explicit:
        return explicit.strip()
    env_sha = os.environ.get("GITHUB_SHA", "").strip()
    if env_sha:
        return env_sha
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def verify_vcpkg_commit(vcpkg_root: Path, expected_commit: str) -> None:
    if not vcpkg_root.is_dir():
        raise RuntimeError(f"vcpkg root directory does not exist: {vcpkg_root}")
    out = subprocess.run(
        ["git", "-C", str(vcpkg_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    actual = out.stdout.strip()
    if actual != expected_commit:
        raise RuntimeError(
            f"vcpkg commit mismatch: {vcpkg_root} is at {actual}, expected {expected_commit}"
        )


def read_port_metadata(
    vcpkg_root: Path, port_name: str, port_dir: str | None = None
) -> tuple[str, str]:
    port_json = (
        (REPO_ROOT / port_dir / "vcpkg.json")
        if port_dir
        else (vcpkg_root / "ports" / port_name / "vcpkg.json")
    )
    data = json.loads(port_json.read_text(encoding="utf-8"))
    version = None
    for k in ("version", "version-semver", "version-string", "version-date"):
        if k in data:
            version = str(data[k])
            break
    if not version:
        raise RuntimeError(f"No version field in {port_json}")
    lic = str(data.get("license") or "See licence file")
    return version, lic


def is_signing_configured() -> bool:
    if os.name == "nt":
        cert = os.environ.get("MIE_WIN_CODESIGN_CERT", "").strip()
        ts = os.environ.get("MIE_WIN_CODESIGN_TIMESTAMP_URL", "").strip()
        return bool(cert and ts)
    return bool(os.environ.get("MIE_LINUX_GPG_KEY_ID", "").strip())


def find_vs_tools() -> tuple[Path, list[Path]]:
    pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    vswhere = pf86 / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        raise RuntimeError(f"vswhere.exe not found at {vswhere}")
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
    dumpbins = sorted(
        (vs_root / "VC" / "Tools" / "MSVC").glob("*/bin/Hostx64/x64/dumpbin.exe")
    )
    if not dumpbins:
        raise RuntimeError(f"dumpbin.exe not found under {vs_root}")
    crt_dirs = sorted(
        (vs_root / "VC" / "Redist" / "MSVC").glob("*/x64/Microsoft.VC*.CRT"),
        reverse=True,
    )
    if not crt_dirs:
        raise RuntimeError(f"MSVC Redist CRT directory not found under {vs_root}")
    return dumpbins[-1], crt_dirs


def parse_dumpbin_dependents(dumpbin: Path, binary: Path) -> list[str]:
    out = subprocess.run(
        [str(dumpbin), "/dependents", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    deps: list[str] = []
    in_deps = False
    for line in out.stdout.splitlines():
        stripped = line.strip()
        if "Image has the following dependencies:" in line or "delay load dependencies:" in line:
            in_deps = True
            continue
        if in_deps and stripped.startswith("Summary"):
            break
        if in_deps and stripped.lower().endswith(".dll") and " " not in stripped:
            deps.append(stripped)
    return deps


def windows_system32_provides(dll_name: str) -> bool:
    low = dll_name.lower()
    if low.startswith("api-ms-win-") or low.startswith("ext-ms-win-"):
        return True
    sys32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    if (sys32 / dll_name).is_file():
        return True
    # LOAD_LIBRARY_AS_DATAFILE (0x2) | LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800)
    handle = ctypes.windll.kernel32.LoadLibraryExW(dll_name, None, 0x00000802)
    if handle:
        ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(handle))
        return True
    return False


def stage_windows_shared_libs(
    stage_dir: Path, build_dir: Path, initial_binaries: list[Path], with_ui: bool
) -> list[str]:
    dumpbin, crt_dirs = find_vs_tools()
    search_dirs: list[Path] = [build_dir / "Release", build_dir]
    for bin_dir in sorted((build_dir / "vcpkg_installed").glob("*/bin")):
        if bin_dir.is_dir():
            search_dirs.append(bin_dir)

    lookup: dict[str, tuple[Path, str]] = {}
    for d in crt_dirs:
        for dll in d.glob("*.dll"):
            lookup.setdefault(dll.name.lower(), (dll, "msvc-crt"))
    # Prefer vcpkg/build DLLs for third-party dependencies, CRT Redist for MSVC runtime
    for d in reversed(search_dirs):
        if d.is_dir():
            for dll in d.glob("*.dll"):
                lookup[dll.name.lower()] = (dll, "vcpkg")

    staged_crt: list[str] = []
    queue: list[Path] = list(initial_binaries)
    seen: set[str] = {p.name.lower() for p in initial_binaries}

    if with_ui:
        # Stage Qt Windows platform plugin as separate replaceable file
        qwin_candidates = list(
            (build_dir / "vcpkg_installed").glob("*/Qt6/plugins/platforms/qwindows.dll")
        ) + list((build_dir / "vcpkg_installed").glob("*/plugins/platforms/qwindows.dll"))
        if not qwin_candidates:
            raise RuntimeError("WITH_UI=ON: qwindows.dll platform plugin not found in vcpkg_installed")
        plat_dir = stage_dir / "plugins" / "platforms"
        plat_dir.mkdir(parents=True, exist_ok=True)
        qwin_dst = plat_dir / "qwindows.dll"
        shutil.copy2(qwin_candidates[0], qwin_dst)
        queue.append(qwin_dst)
        (stage_dir / "qt.conf").write_text("[Paths]\r\nPlugins = plugins\r\n", encoding="utf-8")

    while queue:
        current = queue.pop(0)
        deps = parse_dumpbin_dependents(dumpbin, current)
        if with_ui and current.name.lower() == "mie-ui.exe":
            lower_deps = {d.lower() for d in deps}
            for req_qt in ("qt6core.dll", "qt6gui.dll", "qt6widgets.dll"):
                if req_qt not in lower_deps:
                    raise RuntimeError(
                        f"WITH_UI=ON: {req_qt} is not dynamically linked by mie-ui.exe (static Qt is forbidden)"
                    )
        for dep in deps:
            dep_low = dep.lower()
            if dep_low in seen:
                continue
            if dep_low in lookup:
                src_path, origin = lookup[dep_low]
                dst_path = stage_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                seen.add(dep_low)
                seen.add(src_path.name.lower())
                if origin == "msvc-crt":
                    staged_crt.append(src_path.name)
                queue.append(dst_path)
            elif windows_system32_provides(dep):
                seen.add(dep_low)
            else:
                raise RuntimeError(
                    f"Dependency {dep} of {current.name} was not found in vcpkg, MSVC Redist, or System32"
                )
    return sorted(set(staged_crt))


def is_linux_system_lib(resolved_path: str) -> bool:
    p = os.path.realpath(resolved_path)
    system_prefixes = (
        "/lib/",
        "/lib64/",
        "/usr/lib/",
        "/usr/lib64/",
    )
    base = os.path.basename(p)
    if base.startswith(("libc.so", "libm.so", "libdl.so", "libpthread.so", "librt.so", "ld-linux", "libstdc++.so", "libgcc_s.so")):
        return True
    return p.startswith(system_prefixes)


def strip_elf(path: Path) -> None:
    subprocess.run(["strip", "--strip-unneeded", str(path)], check=True)


def stage_linux_shared_libs(
    stage_dir: Path, build_dir: Path, initial_binaries: list[Path], with_ui: bool
) -> None:
    for b in initial_binaries:
        strip_elf(b)

    queue: list[Path] = list(initial_binaries)
    lib_dir = stage_dir / "lib"

    if with_ui:
        qxcb_candidates = list(
            (build_dir / "vcpkg_installed").glob("*/Qt6/plugins/platforms/libqxcb.so")
        ) + list((build_dir / "vcpkg_installed").glob("*/plugins/platforms/libqxcb.so"))
        if not qxcb_candidates:
            raise RuntimeError("WITH_UI=ON: libqxcb.so platform plugin not found in vcpkg_installed")
        plat_dir = stage_dir / "plugins" / "platforms"
        plat_dir.mkdir(parents=True, exist_ok=True)
        qxcb_dst = plat_dir / "libqxcb.so"
        shutil.copy2(qxcb_candidates[0], qxcb_dst)
        strip_elf(qxcb_dst)
        os.chmod(qxcb_dst, 0o755)
        queue.append(qxcb_dst)
        (stage_dir / "qt.conf").write_text(
            "[Paths]\nPlugins = plugins\nLibraries = lib\n", encoding="utf-8"
        )

    vcpkg_lib_dirs = [
        str(p) for p in sorted((build_dir / "vcpkg_installed").glob("*/lib")) if p.is_dir()
    ]
    env = os.environ.copy()
    if vcpkg_lib_dirs:
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = ":".join(vcpkg_lib_dirs + ([existing] if existing else []))

    staged_libs: set[str] = set()
    while queue:
        current = queue.pop(0)
        if with_ui and current.name == "mie-ui":
            dyn = subprocess.run(
                ["readelf", "-d", str(current)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            for req_qt in ("libQt6Core.so", "libQt6Gui.so", "libQt6Widgets.so"):
                if req_qt not in dyn:
                    raise RuntimeError(
                        f"WITH_UI=ON: {req_qt} is not dynamically linked by mie-ui (static Qt is forbidden)"
                    )

        out = subprocess.run(
            ["ldd", str(current)], check=True, capture_output=True, text=True, env=env
        )
        for line in out.stdout.splitlines():
            line = line.strip()
            if "not found" in line:
                raise RuntimeError(f"Missing shared library in ldd {current}: {line}")
            if "=>" not in line:
                continue
            soname, rhs = [part.strip() for part in line.split("=>", 1)]
            resolved = rhs.split("(", 1)[0].strip()
            if not resolved or not resolved.startswith("/"):
                continue
            if is_linux_system_lib(resolved):
                continue
            if soname in staged_libs:
                continue
            lib_dir.mkdir(parents=True, exist_ok=True)
            dst = lib_dir / soname
            shutil.copy2(os.path.realpath(resolved), dst)
            strip_elf(dst)
            os.chmod(dst, 0o755)
            staged_libs.add(soname)
            queue.append(dst)


def find_vcpkg_copyright(build_dir: Path, port_name: str) -> Path:
    variants = [port_name, port_name.replace("-", "_")]
    for variant in variants:
        matches = sorted(
            (build_dir / "vcpkg_installed").glob(f"*/share/{variant}/copyright")
        )
        if matches:
            return matches[0]
    raise RuntimeError(
        f"Could not find installed vcpkg copyright file for port {port_name!r} under {build_dir / 'vcpkg_installed'}"
    )


def populate_licenses(
    stage_dir: Path,
    build_dir: Path,
    vcpkg_root: Path,
    pins: dict,
    with_ui: bool,
    staged_crt: list[str],
) -> None:
    licenses_dir = stage_dir / "licenses"
    licenses_dir.mkdir(parents=True, exist_ok=True)

    nl = "\r\n" if os.name == "nt" else "\n"
    notice_lines = [
        "Dexmond MIE - Third-Party Software Notices",
        "==========================================",
        "",
        f"Pinned vcpkg registry commit: {pins['vcpkg_commit']}",
        "",
    ]

    for name, meta in pins["libraries"].items():
        if not meta.get("shipped", True):
            continue
        port_ver, port_lic = read_port_metadata(vcpkg_root, name, meta.get("port_dir"))
        expected_ver = meta["expected_version"]
        expected_commit = meta["expected_commit"]
        if port_ver != expected_ver:
            raise RuntimeError(
                f"Version mismatch for {name}: vcpkg port has {port_ver}, pins.json expects {expected_ver}"
            )
        src_copyright = find_vcpkg_copyright(build_dir, name)
        dst_lic_name = f"{name}-LICENSE.txt"
        dst_lic = licenses_dir / dst_lic_name
        lic_text = src_copyright.read_text(encoding="utf-8", errors="replace")
        dst_lic.write_bytes(lic_text.replace("\r\n", "\n").replace("\n", nl).encode("utf-8"))

        notice_lines.extend(
            [
                f"Component: {name}",
                f"  Version:         {expected_ver}",
                f"  Upstream repo:   {meta['repository']}",
                f"  Upstream commit: {expected_commit}",
                f"  Licence:         {port_lic}",
                f"  Licence text:    licenses/{dst_lic_name}",
                "",
            ]
        )

    if with_ui:
        qt_ver, _ = read_port_metadata(vcpkg_root, "qtbase")
        qt_copyright = find_vcpkg_copyright(build_dir, "qtbase")
        qt_lic_dst = licenses_dir / "qtbase-LICENSE.txt"
        qt_lic_dst.write_bytes(
            qt_copyright.read_text(encoding="utf-8", errors="replace")
            .replace("\r\n", "\n")
            .replace("\n", nl)
            .encode("utf-8")
        )
        for fname in (
            "LGPL-3.0.txt",
            "GPL-3.0.txt",
            "QT-LGPL-NOTICE.txt",
            "QT-SOURCE-OFFER.txt",
        ):
            src = LEGAL_DIR / fname
            if not src.is_file():
                raise RuntimeError(f"Missing required Qt legal file: {src}")
            (licenses_dir / fname).write_bytes(
                src.read_text(encoding="utf-8")
                .replace("\r\n", "\n")
                .replace("\n", nl)
                .encode("utf-8")
            )
        notice_lines.extend(
            [
                "Component: qtbase (Qt Core, Qt Gui, Qt Widgets, platform plugin)",
                f"  Version:         {qt_ver}",
                "  Upstream repo:   https://code.qt.io/qt/qtbase.git",
                f"  Upstream tag:    v{qt_ver} (vcpkg commit {pins['vcpkg_commit']})",
                "  Licence:         LGPL-3.0-only (dynamic shared libraries, replaceable)",
                "  Licence text:    licenses/LGPL-3.0.txt, licenses/GPL-3.0.txt, licenses/qtbase-LICENSE.txt",
                "  Source offer:    licenses/QT-SOURCE-OFFER.txt",
                "  LGPL notice:     licenses/QT-LGPL-NOTICE.txt",
                "",
            ]
        )

    if os.name == "nt" and staged_crt:
        notice_lines.extend(
            [
                "Runtime Libraries (Windows app-local C++ runtime):",
                f"  Files: {', '.join(staged_crt)}",
                "  Provided from Microsoft Visual Studio VC Redistributable directory.",
                "",
            ]
        )

    (licenses_dir / "THIRD-PARTY-NOTICES.txt").write_bytes(
        nl.join(notice_lines).encode("utf-8")
    )


def write_readme(
    stage_dir: Path,
    wording: dict,
    version: str,
    short_sha: str,
    signed: bool,
    with_ui: bool,
) -> None:
    nl = "\r\n" if os.name == "nt" else "\n"
    fs = wording["fixed_sentences"]
    lines: list[str] = []
    if not signed:
        lines.append(wording["unsigned_banner"])
        lines.append(wording["unsigned_notice"])
        lines.append("")

    lines.append(f"{wording['product_name']} {version} ({short_sha})")
    lines.append(f"Publisher: {wording['publisher']}")
    lines.append("")
    lines.append(fs["what_it_does"])
    lines.append("")
    lines.append(fs["account_boundary"])
    lines.append("")
    if os.name != "nt":
        lines.append(fs["linux_scope"])
        lines.append("")
    lines.append(fs["no_scan_engine"])
    lines.append("")

    plat_cfg = wording["windows"] if os.name == "nt" else wording["linux"]
    lines.append(plat_cfg["install_location_note"])
    lines.append(plat_cfg["userdata_location_note"])
    lines.append("")
    lines.append(wording["common"]["licenses_note"])
    if with_ui:
        lines.append(wording["common"]["qt_replaceable_note"])
    lines.append("")

    (stage_dir / "README.txt").write_bytes(nl.join(lines).encode("utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and stage Dexmond MIE install tree")
    parser.add_argument("--build-dir", default="build-pkg/engine-build")
    parser.add_argument("--stage-dir", default="build-pkg/stage")
    parser.add_argument("--manifest", default="build-pkg/stage-manifest.json")
    parser.add_argument(
        "--vcpkg-root",
        default=os.environ.get("VCPKG_ROOT", str(REPO_ROOT / ".vcpkg")),
    )
    parser.add_argument(
        "--with-ui",
        nargs="?",
        const=True,
        default=parse_bool_flag(os.environ.get("WITH_UI", "OFF")),
        type=parse_bool_flag,
        help="Stage mie-ui and Qt 6 LGPL shared libraries/notices (default OFF)",
    )
    parser.add_argument("--commit", default=None)
    args = parser.parse_args()

    version = read_project_version()
    commit = resolve_commit(args.commit)
    short_sha = commit[:7]
    pins = json.loads(PINS_FILE.read_text(encoding="utf-8"))
    wording = json.loads(WORDING_FILE.read_text(encoding="utf-8"))
    vcpkg_root = Path(args.vcpkg_root).resolve()
    build_dir = Path(args.build_dir).resolve()
    stage_dir = Path(args.stage_dir).resolve()
    manifest_path = Path(args.manifest).resolve()

    verify_vcpkg_commit(vcpkg_root, pins["vcpkg_commit"])

    if args.with_ui:
        cmake_src = CMAKE_FILE.read_text(encoding="utf-8")
        if "mie-ui" not in cmake_src:
            print(
                "ERROR: WITH_UI=ON requested, but target 'mie-ui' does not exist in "
                f"{CMAKE_FILE} on this branch.",
                file=sys.stderr,
            )
            return 2

    toolchain = vcpkg_root / "scripts" / "buildsystems" / "vcpkg.cmake"
    cmake_cmd = [
        "cmake",
        "-S",
        str(ENGINE_DIR),
        "-B",
        str(build_dir),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DMIE_BUILD_TESTS=OFF",
        "-DMIE_WITH_RULES=ON",
        "-DVCPKG_MANIFEST_FEATURES=rules",
        f"-DVCPKG_OVERLAY_PORTS={ENGINE_DIR / 'vcpkg-ports'}",
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        f"-DMIE_REPO_ROOT={REPO_ROOT}",
        f"-DPython3_EXECUTABLE={sys.executable}",
    ]
    if args.with_ui:
        cmake_cmd.append("-DWITH_UI=ON")
    if os.name != "nt":
        cmake_cmd.append("-DCMAKE_EXE_LINKER_FLAGS=-Wl,-z,relro,-z,now")
        if args.with_ui:
            cmake_cmd.extend(
                [
                    "-DCMAKE_BUILD_RPATH=$ORIGIN:$ORIGIN/lib",
                    "-DCMAKE_INSTALL_RPATH=$ORIGIN:$ORIGIN/lib",
                    "-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON",
                ]
            )
        else:
            cmake_cmd.append("-DCMAKE_SKIP_RPATH=ON")

    print("Configuring CMake:", " ".join(cmake_cmd), flush=True)
    subprocess.run(cmake_cmd, check=True)

    targets = ["mie-service", "mie", "mie-worker"]
    if args.with_ui:
        targets.append("mie-ui")
    build_cmd = [
        "cmake",
        "--build",
        str(build_dir),
        "--config",
        "Release",
        "--parallel",
        "4",
        "--target",
        *targets,
    ]
    print("Building targets:", " ".join(build_cmd), flush=True)
    subprocess.run(build_cmd, check=True)

    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    exe_suffix = ".exe" if os.name == "nt" else ""
    staged_programs: list[Path] = []
    for target in targets:
        fname = f"{target}{exe_suffix}"
        candidates = [build_dir / "Release" / fname, build_dir / fname]
        src = next((c for c in candidates if c.is_file()), None)
        if src is None:
            raise RuntimeError(f"Built program {fname} not found in {candidates}")
        dst = stage_dir / fname
        shutil.copy2(src, dst)
        if os.name != "nt":
            os.chmod(dst, 0o755)
        staged_programs.append(dst)

    # Explicitly assert mie-worker is staged and NO test/sandbox/probe binaries exist
    wkr_ok, wkr_detail = check_worker_and_no_forbidden_programs(stage_dir, exe_suffix)
    if not wkr_ok:
        raise RuntimeError(wkr_detail)

    staged_crt: list[str] = []
    if os.name == "nt":
        staged_crt = stage_windows_shared_libs(
            stage_dir, build_dir, staged_programs, args.with_ui
        )
    else:
        stage_linux_shared_libs(stage_dir, build_dir, staged_programs, args.with_ui)

    signed = is_signing_configured()
    populate_licenses(
        stage_dir, build_dir, vcpkg_root, pins, args.with_ui, staged_crt
    )
    write_readme(stage_dir, wording, version, short_sha, signed, args.with_ui)

    files_manifest = []
    for p in sorted(stage_dir.rglob("*")):
        if p.is_file():
            rel = p.relative_to(stage_dir).as_posix()
            files_manifest.append(
                {
                    "path": rel,
                    "size": p.stat().st_size,
                    "sha256": sha256_file(p),
                }
            )

    manifest = {
        "product_name": wording["product_name"],
        "publisher": wording["publisher"],
        "version": version,
        "commit": commit,
        "short_sha": short_sha,
        "platform": "windows" if os.name == "nt" else "linux",
        "with_ui": bool(args.with_ui),
        "signed": signed,
        "stage_dir": str(stage_dir),
        "staged_crt": staged_crt,
        "files": files_manifest,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Staged {len(files_manifest)} files into {stage_dir}:", flush=True)
    for entry in files_manifest:
        print(f"  {entry['path']} ({entry['size']} bytes, sha256={entry['sha256']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
