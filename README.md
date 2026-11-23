# DEXMOND MIE — Malware Inspection Engine

Licensed under the Apache License 2.0 (see `LICENSE`; attributions in `NOTICE` and `THIRD-PARTY-NOTICES`).

Product and tool names in the detection rules are used only to identify what a rule detects. They are trademarks of their owners. Dexmond is not affiliated with them.

Some rules match patterns associated with dual-use security tools that are also used legitimately (e.g. in authorised penetration testing). A match is not a finding of malicious intent.

A second-opinion file scanner for Windows with a local web dashboard. It reads
file bytes and checks them with its own YARA pattern rules, simple
heuristics and a known-hash list, can watch four user folders for new files,
and can move a flagged file into a quarantine folder.

## Features

- **Scan pipeline** — MD5/SHA1/SHA256 hashing, Shannon entropy, YARA matching
  (15 rules in `rules/`), PE (Windows executable) analysis, string/IOC
  extraction, weighted scoring. Verdicts: CLEAN, SUSPICIOUS (LOW / MEDIUM),
  MALICIOUS.
- **Known-hash list** — `data/reputation.json` (today: the two EICAR test-file
  hashes). A file the user quarantines is added as known-bad; a file the user
  restores is added as trusted, and a trusted hash is reported CLEAN from then
  on without being scanned.
- **Archive scanning** — looks inside `.zip` and `.tar` (also `.jar`, `.tgz`
  and similar), with path checks against zip-slip and member, size and depth
  limits against zip bombs.
- **Folder monitoring** — while the app is running, scans files created in or
  moved into Downloads, Desktop, Documents and Temp, after they are written.
  Files changed in place are not rescanned, and nothing is blocked before it
  is opened. Optional auto-quarantine of files judged MALICIOUS (off by
  default).
- **Quarantine** — moves the file into the quarantine folder as a copy XOR-ed
  with one fixed byte (obfuscation, not encryption) so it is not run or
  re-flagged by accident, deletes the original, and can restore it exactly
  or delete it.
- **Web dashboard** — at `http://localhost:8888`, reachable from this computer
  only.
- **Local access control** — every command endpoint requires a per-machine
  access token (stored `0600`); a loopback-only host check blocks DNS rebinding.

## Limits (read before relying on it)

- Detection of real malware has **not been measured**. It has been tested only
  with the harmless EICAR test files and synthetic samples.
- It does not replace your regular security software (for example Microsoft
  Defender): keep that turned on.
- No driver and no on-access blocking: it does not watch memory, processes,
  the registry or the boot sector, and it scans a file only after it is on
  disk.
- No automatic updates of the program or the rules; a new version is a new
  download.
- Normal files can be flagged (false alarms). The false-alarm rate of this
  version has not yet been re-measured; see `RELEASE_GAPS.md`.

## Requirements

- Python 3.10+ (3.11 or 3.12 recommended)
- On Windows, the desktop window uses **WebView2**, which ships with current
  Windows 10/11. If missing, install the "Evergreen WebView2 Runtime" from
  Microsoft.

## Run from source

```bat
git clone https://github.com/Dexmond-Technologies/MIE.git
cd MIE
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python main.py gui            :: full app: dashboard window + tray + folder monitoring
python main.py background     :: tray + folder monitoring, no window
python main.py scan <path>    :: one-off scan of a file or folder (add --output json)
```

The dashboard is always reachable in a browser at `http://localhost:8888`
while the app is running. Set `DEXMOND_PORT` to change the port.

## Where data is stored

| | Running from source | Packaged `.exe` |
|---|---|---|
| YARA rules | `./rules` | bundled inside the app |
| Reputation seed | `./data/reputation.json` | bundled, copied to app-data on first run |
| Token / state / quarantine | `./data`, `./quarantine` | `%LOCALAPPDATA%\DexmondMIE` |

Runtime files (the auth token, live state, quarantined files) are never
committed to git — see `.gitignore`.

## Build the Windows package

On a **Windows** machine with the repo cloned and requirements installed:

```bat
pip install -r requirements-windows-build.txt
pip install --require-hashes -r requirements-signify.lock
pyinstaller dexmond_mie.spec
python scripts\check_bundle.py dist\DexmondMIE
```

This produces a one-folder build at `dist\DexmondMIE\`. Run
`dist\DexmondMIE\DexmondMIE.exe` to launch. Distribute the whole
`DexmondMIE` folder (or wrap it with an installer such as Inno Setup).

### Before shipping to production

- **Code-sign** `DexmondMIE.exe` with an Authenticode certificate — an unsigned
  security tool is often flagged by SmartScreen and other scanners.
- The GitHub workflow `tests` (job `windows-build`) builds an UNSIGNED TEST
  build with its SHA-256; a sale build needs the production licence key
  (`python scripts/check_release_key.py` must pass).
- Add an application **icon** (`assets/dexmond.ico`, referenced in the `.spec`).
- Test the packaged build on a clean Windows VM (the window, tray, folder
  monitoring and quarantine paths have not yet been exercised on Windows).
- Consider an installer that sets **auto-start on login**; without it, folder
  monitoring runs only after the user starts the app.

## Testing safely

Use the standard **EICAR** test file (a harmless file defined by EICAR for
testing scanners) to check detection without touching real malware.
