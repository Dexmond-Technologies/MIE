#!/usr/bin/env python3
"""Shared verification helpers for Dexmond MIE packaging acceptance tests.

Implements the cross-platform checks used by both Windows (P-7, P-8, P-9)
and Linux (L-8):
  - Third-party licences & THIRD-PARTY-NOTICES.txt against engine/third_party/pins.json
  - Qt LGPL draft files presence and "DRAFT, not legal text" header check
  - Wording check (zero forbidden words; exact fixed sentences present)
  - Signing placeholder skip log & absence of keys/certificates/signatures
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

PACKAGING_DIR = Path(__file__).resolve().parent
ENGINE_DIR = PACKAGING_DIR.parent
REPO_ROOT = ENGINE_DIR.parent
PINS_PATH = ENGINE_DIR / "third_party" / "pins.json"
WORDING_PATH = PACKAGING_DIR / "wording.json"
ISS_PATH = PACKAGING_DIR / "windows" / "mie.iss"
LEGAL_DIR = PACKAGING_DIR / "legal"

EXPECTED_FIXED_SENTENCES = {
    "what_it_does": (
        "Dexmond MIE checks files and reports what it finds. "
        "It has not been tested against real malware."
    ),
    "account_boundary": (
        "Other user accounts on this computer cannot control MIE. "
        "Programs that run under your own account can."
    ),
    "linux_scope": (
        "This version does not judge Linux programs. "
        "It checks Windows programs, scripts, documents and archives."
    ),
    "no_scan_engine": (
        "This build contains the background service and the command line only. "
        "The scan engine is not part of this build. Nothing is being scanned."
    ),
}

FORBIDDEN_PATTERNS = [
    (r"\bantivirus\b", "antivirus"),
    (r"\banti-virus\b", "anti-virus"),
    (r"\bprotected\b", "protected"),
    (r"\bprotection\b", "protection"),
    (r"\breal-time\b", "real-time"),
    (r"\brealtime\b", "realtime"),
    (r"\breal\s+time\b", "real time"),
    (r"100%", "100%"),
    (r"\bsecure\b", "secure"),
    (r"\bsafe\b", "safe"),
    (r"may\s+not\s+reverse\s+engineer", "may not reverse engineer"),
    (r"do\s+not\s+reverse\s+engineer", "do not reverse engineer"),
    (r"no\s+reverse\s+engineering", "no reverse engineering"),
    (
        r"\b\d+(?:\.\d+)?\s*(?:mb/s|gb/s|kb/s|mib/s|files/s|files\s+per\s+second|"
        r"milliseconds|\bms\b|mb\s+of\s+ram|gb\s+of\s+ram|megabytes\s+of\s+memory)\b",
        "speed/memory figure",
    ),
]

FORBIDDEN_KEY_OR_SIG_SUFFIXES = {
    ".pfx",
    ".p12",
    ".pem",
    ".key",
    ".jks",
    ".keystore",
    ".cer",
    ".crt",
    ".asc",
    ".sig",
    ".gpg",
}

FORBIDDEN_PROGRAM_PREFIXES = (
    "mie-worker-testhooks",
    "mie-worker-run",
    "mie-sandbox-",
    "mie-probe",
    "mie-pe-probe",
    "mie-signature-probe",
    "mie-archive-probe",
    "mie-pe-analysis-probe",
    "mie-scoring-check",
    "mie-parity-run",
    "mie_tests",
    "fuzz_",
)


def is_forbidden_program_name(filename: str) -> bool:
    low = filename.lower()
    stem = low[:-4] if low.endswith(".exe") else low
    for prefix in FORBIDDEN_PROGRAM_PREFIXES:
        if prefix.endswith("-") or prefix.endswith("_"):
            if low.startswith(prefix) or stem.startswith(prefix):
                return True
        else:
            if stem == prefix or low == prefix:
                return True
    return False


def check_worker_and_no_forbidden_programs(
    tree_dir: Path, exe_suffix: str, require_worker: bool = True
) -> tuple[bool, str]:
    """Verify `mie-worker` exists (when required) and no test/sandbox/probe program exists."""
    errors: list[str] = []
    worker_name = f"mie-worker{exe_suffix}"
    if require_worker:
        worker_path = tree_dir / worker_name
        if not worker_path.is_file() or worker_path.stat().st_size == 0:
            errors.append(f"missing or empty {worker_name} in {tree_dir}")

    forbidden_found: list[str] = []
    if tree_dir.is_dir():
        for p in sorted(tree_dir.rglob("*")):
            if is_forbidden_program_name(p.name):
                forbidden_found.append(p.relative_to(tree_dir).as_posix())
    if forbidden_found:
        errors.append(f"forbidden test programs found in {tree_dir}: {forbidden_found}")

    if errors:
        return False, "; ".join(errors)
    return (
        True,
        f"{worker_name if require_worker else 'tree'} verified in {tree_dir.name}; "
        "zero forbidden test/sandbox programs present",
    )


def check_licenses_and_notices(stage_dir: Path) -> tuple[bool, str]:
    """Verify P-7 / L-8(licences): licenses/ texts + THIRD-PARTY-NOTICES.txt + DRAFT legal files."""
    errors: list[str] = []
    pins = json.loads(PINS_PATH.read_text(encoding="utf-8"))
    licenses_dir = stage_dir / "licenses"
    if not licenses_dir.is_dir():
        return False, f"missing licenses directory: {licenses_dir}"

    notices_file = licenses_dir / "THIRD-PARTY-NOTICES.txt"
    if not notices_file.is_file():
        return False, f"missing {notices_file}"
    notices_text = notices_file.read_text(encoding="utf-8")

    for name, meta in pins["libraries"].items():
        if not meta.get("shipped", True):
            continue
        lic_file = licenses_dir / f"{name}-LICENSE.txt"
        if not lic_file.is_file() or lic_file.stat().st_size < 100:
            errors.append(f"missing or empty licence text for {name}: {lic_file}")
        expected_version = meta["expected_version"]
        expected_commit = meta["expected_commit"]
        if name not in notices_text:
            errors.append(f"THIRD-PARTY-NOTICES.txt missing library name {name}")
        if expected_version not in notices_text:
            errors.append(
                f"THIRD-PARTY-NOTICES.txt missing version {expected_version} for {name}"
            )
        if expected_commit not in notices_text:
            errors.append(
                f"THIRD-PARTY-NOTICES.txt missing commit {expected_commit} for {name}"
            )
        if f"licenses/{name}-LICENSE.txt" not in notices_text:
            errors.append(
                f"THIRD-PARTY-NOTICES.txt missing licence path for {name}"
            )

    # Also verify the 4 prepared Qt LGPL duty files exist in engine/packaging/legal/
    # and carry "DRAFT, not legal text" on line 1.
    for fname in (
        "LGPL-3.0.txt",
        "GPL-3.0.txt",
        "QT-LGPL-NOTICE.txt",
        "QT-SOURCE-OFFER.txt",
    ):
        fpath = LEGAL_DIR / fname
        if not fpath.is_file():
            errors.append(f"missing prepared Qt legal file {fpath}")
            continue
        first_line = fpath.read_text(encoding="utf-8").splitlines()[0].strip()
        if first_line != "DRAFT, not legal text":
            errors.append(
                f"{fname} first line is {first_line!r}, expected 'DRAFT, not legal text'"
            )

    if errors:
        return False, "; ".join(errors)
    return (
        True,
        "all shipped third-party licences and THIRD-PARTY-NOTICES.txt match pins.json; "
        "Qt LGPL draft files verified",
    )


def find_forbidden_words(text: str, label: str) -> list[str]:
    found: list[str] = []
    for pattern, desc in FORBIDDEN_PATTERNS:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            found.append(f"{label} contains forbidden term {desc!r} ({m.group(0)!r})")
    return found


def check_wording(
    platform_kind: str,
    readme_path: Path,
    extra_texts: Iterable[tuple[str, str]] = (),
    debian_control_description: str | None = None,
) -> tuple[bool, str]:
    """Verify P-8 / L-8(wording): wording.json, mie.iss, README.txt, and installer/deb texts."""
    errors: list[str] = []

    raw_wording = WORDING_PATH.read_text(encoding="utf-8")
    wording = json.loads(raw_wording)
    iss_text = ISS_PATH.read_text(encoding="utf-8")
    readme_text = readme_path.read_text(encoding="utf-8")

    errors.extend(find_forbidden_words(raw_wording, "wording.json"))
    errors.extend(find_forbidden_words(iss_text, "windows/mie.iss"))
    errors.extend(find_forbidden_words(readme_text, str(readme_path.name)))

    for label, content in extra_texts:
        errors.extend(find_forbidden_words(content, label))

    # Check exact character-for-character fixed sentences in wording.json
    fs = wording.get("fixed_sentences", {})
    for key, expected in EXPECTED_FIXED_SENTENCES.items():
        actual = fs.get(key)
        if actual != expected:
            errors.append(
                f"wording.json fixed_sentences[{key!r}] != expected ({actual!r} != {expected!r})"
            )

    # Check README.txt sentences
    for key in ("what_it_does", "account_boundary", "no_scan_engine"):
        if EXPECTED_FIXED_SENTENCES[key] not in readme_text:
            errors.append(f"README.txt missing exact sentence {key!r}")

    if platform_kind == "linux":
        if EXPECTED_FIXED_SENTENCES["linux_scope"] not in readme_text:
            errors.append("Linux README.txt missing exact linux_scope sentence")
    elif platform_kind == "windows":
        if EXPECTED_FIXED_SENTENCES["linux_scope"] in readme_text:
            errors.append("Windows README.txt unexpectedly contains Linux-only sentence")

    if debian_control_description is not None:
        errors.extend(find_forbidden_words(debian_control_description, "DEBIAN/control Description"))
        normalized_desc = " ".join(debian_control_description.split())
        for key in ("what_it_does", "account_boundary", "linux_scope", "no_scan_engine"):
            if EXPECTED_FIXED_SENTENCES[key] not in normalized_desc:
                errors.append(f"DEBIAN/control Description missing exact sentence {key!r}")

    if errors:
        return False, "; ".join(errors)
    return True, "no forbidden words found; all fixed sentences match character-for-character"


def find_created_keys_or_signatures(roots: Iterable[Path]) -> list[str]:
    """Scan build/stage/output folders to ensure no cert, key or signature file was created."""
    bad: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() in FORBIDDEN_KEY_OR_SIG_SUFFIXES:
                bad.append(str(p))
    return bad
