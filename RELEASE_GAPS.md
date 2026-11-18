# MIE: release gaps (branch release/mie-sale, 2026-11-18)

Status words: DONE = committed here; NOT RUN = written but not executed by its author;
OPEN = needs a person or a decision. Nothing on this branch was run locally: Python files
were only syntax-checked (`python3 -I -m py_compile`). Tests and the Windows build run in
GitHub CI (workflow `tests`, manual trigger).

## 1. Done on this branch (all NOT RUN until CI is green)

| Item | Commit | What |
|---|---|---|
| CI failures of run 43558751324 | 08df58f, see below | Linux: an oversize file whose window matched a rule but scored LOW was labelled "oversize, partially scanned" (meant for "nothing found"). Windows: `read_for_verify` followed symbolic links (no `O_NOFOLLOW` on Windows); now lstat + refusal of symlinks/junctions (name-surrogate reparse tags only, so OneDrive cloud files are still verified) + same-file check. Both were product bugs; the tests were right. INC-2026-11-14-002 stays OPEN until a green run. |
| False alarms FA-1, FA-2 | 1e9d8ca, 1366527 | See section 2. |
| Windows build in CI | 72c6efd | Job `windows-build`: full pytest on Windows, PyInstaller one-folder build without UPX, static bundle check (`scripts/check_bundle.py`), zip + SHA-256, artefact kept 14 days. |
| Licence by activation code | 8c5b2d2 | `dexmond_mie/licence.py`, `dexmond_mie/licence_key.py`, `scripts/check_release_key.py`, CI gate step. Not wired into the app (MIE has no paid tier). |
| Texts | 0c67952 | Dashboard, README, logs say what the code does. |

## 2. False alarms: what changed and why

Evidence used: the per-file results of the final candidate 32d1c4d (categories per file, no
finding texts), a local COPY found in another session's scratchpad, not checked against the
x455 originals:
- `final-v1-20261114T0433/run1.jsonl` sha256 `eacd71b2273dc1119232eb3de64a0e7b66557a61ba75cf8ce1f1fba1bf016c8f`
- `final-bprime-20261114T0433/run1.jsonl` sha256 `937b1072ef1526434ba87a2e50ce58fe254fa4cb6565c770232574a1ccdd1658`

All 18 remaining MEDIUM benign files (v1: MinGit 9, Sysinternals 3, python-embed 1; B':
Notepad++ 2, VLC 2, UPX 1) carry `suspicious_string` (5 points per key, its own family, so
it adds on top of the capped imports family). It also fires alone on 95 LOW v1 files,
including Linux ELF files and documents.

- **FA-1, API-name strings in a PE (core.py, pe_analyzer.py).** The import hint/name table
  holds every imported API name as a plain string, so `suspicious_api` re-scored imports that
  the import analysis already judged, and re-added `VirtualAlloc`, which fix X3 removed from
  single imports on purpose. Now only the string run that starts and ends exactly at the
  name entry of an import the import analysis SCORED (a `SUSPICIOUS_IMPORTS` name, or an API
  of a chain that was reported) is skipped. After the security review of 1e9d8ca: the same
  name anywhere else in the file, names the import analysis does not score
  (`ReflectiveLoader`, `VirtualAlloc` outside a chain), imports without a known offset,
  UTF-16 strings and non-PE files all still count. Tests: `tests/test_fa_string_iocs.py`
  (two bypass tests included).
  The offsets come from pefile's `ImportData.name_offset`; a Windows-only test checks that
  on the runner's real `python.exe` (if pefile lacked it, FA-1 would suppress nothing).
  Effect on detection: a PE whose ONLY API-name string hit was its own scored import entry
  loses those 5 points; that can move such a file across 30 or 70 (auto-quarantine acts on
  MALICIOUS only). The import evidence itself is still scored in full.
- **FA-2, the "-enc" PowerShell string (utils.py).** It matched "-enc" anywhere:
  "Accept-Encoding", "Content-Encoding", "--encoding", "-encrypt". It now matches `-enc` up to
  `-EncodedCommand` (every prefix PowerShell accepts from -enc on, one or two dashes) only as
  a separate command-line token. The "powershell" / "pwsh" literals are unchanged.

Not changed, on purpose (each would lower detection of what it was written for):
- The imports family cap is 35, above the MEDIUM line of 30, so routine-API evidence alone
  (two minor chains + one single import) reaches MEDIUM. INFERRED (from categories only, no
  finding texts): this is the main remaining cause on B' (Notepad++, VLC Qt plugin). Lowering the cap, sub-capping the minor chains, or moving
  the threshold is a CALIBRATION DECISION for SENTINEL and r-00 (OPEN).
- `dynamic_resolution_chain`, `api_chain`, the publisher allowlist and the trust pins
  (Sysmon and portmon depend on X12, which SENTINEL reviewed).
- msys-2.0.dll really imports the process-injection APIs (Cygwin fork); it is expected to
  stay MEDIUM.

**The false-alarm rate is NOT claimed to be under the limit.** It must be re-measured.

### Exact re-measure (coordinator, on tiny, network off, slot from COMMANDER_SEAT)

The fixes were designed while reading the v1 and B' results, so a run on v1 + B' is a
development check only (LAW 9, r-00 B-2390). An independent result needs a NEW held-out set
B'' (posted with its MANIFEST sha256 before any scan). Runner and corpora are NOT in this
repository. The v1 runner ran as `/home/lenovo-mini/mie-s447/run_mie_test.py` on tiny
(runner.log of run-20261114T0238); v2 is assumed to sit in the same folder. The arguments
marked RUNBOOK are NOT RECORDED in my sources: take them from `RUNBOOK_S447.md`
(sha256 d3757de5...) or `python3 run_mie_test.v2.py --help`.

```sh
# MIE under test: head of release/mie-sale (record the commit id in the result post)
git -C <mie checkout on tiny> fetch origin && git -C <mie checkout on tiny> checkout --detach origin/release/mie-sale
# runner v2 sha256 d3ba3836..., unchanged; pass lines B-2291 + B-2303, unchanged
cd ~/mie-s447
taskset -c 0,1 python3 run_mie_test.v2.py <RUNBOOK: MIE path, output dir>                          # v1 corpus, MANIFEST aa24614e...
taskset -c 0,1 python3 run_mie_test.v2.py <RUNBOOK: benign-only args> --min-b 500 <B' corpus dir> # B', MANIFEST acb09c33...
# G2: EICAR must be matched by YARA with the known-hash list off
taskset -c 0,1 python3 main.py scan <corpus>/M --no-reputation --output json
```

Pass lines (unchanged): at most 10 of 2,005 at SUSPICIOUS (MEDIUM) or above on v1, at most 2
of 500 on B', 0 MALICIOUS in B1/B4/Sysinternals, EICAR 4/4, run 1 = run 2. Then the same on
B''.

## 3. Missing for sale

| # | Gap | Who |
|---|---|---|
| 1 | Green CI run of this branch (Linux, Windows X12, Windows build); then review and merge to `main` | coordinator, SENTINEL |
| 2 | False-alarm re-measure on v1 + B' (command above), then a NEW held-out set B'' | coordinator, SENTINEL, r-00 |
| 3 | Imports-family calibration decision (section 2) | SENTINEL, r-00 |
| 4 | Real-malware detection test plan, designed WITH the security reviewer: lab-held or licensed sample set on an isolated machine, or an outside test lab. No agent handles samples. Until measured, no detection-rate text anywhere | SENTINEL design, owner decides |
| 5 | Missing test classes M2, M4, M5 and the F2 resilience test (B-2417) | SENTINEL, r-00 |
| 6 | Windows smoke test of the CI artefact on a clean Windows machine next to Microsoft Defender: start, dashboard, tray, folder monitoring, quarantine and restore, uninstall; memory and CPU measured. Include scanning a zip that contains an .exe (INFERRED risk: pefile keeps the member mapped, and Windows cannot delete the temp folder of a mapped file) and files in a OneDrive-backed Desktop/Documents. Hidden imports (webview, pythonnet, pystray, uvicorn) only show at first start: `check_bundle.py` does not run the exe | a session with a Windows VM |
| 7 | Installer (none exists; the artefact is a zipped folder), autostart choice, uninstall | a session |
| 8 | Code-signing certificate (until then: unsigned download with a warning and the SHA-256) | owner |
| 9 | Production licence key for product "mie": offline ceremony, then set `LICENSE_PUBLIC_KEY_B64` and `PROD_PUBKEY_SHA256` in `dexmond_mie/licence_key.py`; `scripts/check_release_key.py` must pass; CI run with `sale_build=true` | owner, SENTINEL |
| 10 | ML-DSA-65 verify library for Python (none is a dependency; the default verifier refuses everything) | SENTINEL |
| 11 | Activation service (shared Dexmond service, SALES_ACTIVATION_SERVICE_SPEC_2026-11-18) and its response format; the client assumes `{"licence": ...}` / `{"error": ...}`; set `ACTIVATION_URL` | service session, SENTINEL |
| 12 | The request sends `product`, `code`, `hwid`, `app_version`. The legal text (spec item 7) says code + hardware-id hash only: AGENT-LAW to accept the two extra fields or the client drops them. Privacy text must name the five hardware-id inputs (platform, arch, CPU model, CPU count, host name) | AGENT-LAW |
| 13 | Stripe product and price for MIE, sale page, EULA, withdrawal waiver, EU-only | owner, AGENT-LAW |
| 14 | Rule authorship record: every rule says `author = "DEXMOND MIE"` with no source note; who wrote them and from what is not recorded (first commit da2fef9, 2026-07-20). Needed before sale (licence of any borrowed rule text) | owner, a session |
| 15 | Licence notices for bundled dependencies (pystray LGPL-3.0, mscerts MPL-2.0, PyInstaller bootloader, WebView2 terms); product licence; a full hash-locked lock file for the build (today: exact top-level pins only, `requirements-windows-build.txt`) | AGENT-LAW, a session |
| 16 | Update path for program and rules; support address in the app | a session, owner |
| 17 | Release-level security review (local API, archive handling, quarantine, signature shortcut, activation client) | SENTINEL |

## 4. Open questions for the owner

- **Free tier vs paid tier: OPEN.** MIE has no licence concept today and every feature is
  free ("Free Edition"). Which features a paid licence would unlock is not decided; nothing
  was invented here. The licence module is ready to be wired to that decision.
- What MIE may call itself (the texts now say "second-opinion file scanner"; the product name
  "Malware Inspection Engine" is unchanged).
- Whether to ship with "detection of real malware not measured" stated to users, or wait for
  the measurement (gap 4).
