# DEXMOND MIE — Malware Inspection Engine

Licensed under the Apache License 2.0 (see `LICENSE`; attributions in `NOTICE` and `THIRD-PARTY-NOTICES`).

Product and tool names in the detection rules are used only to identify what a rule detects. They are trademarks of their owners. Dexmond is not affiliated with them.

Some rules match patterns associated with dual-use security tools that are also used legitimately (e.g. in authorised penetration testing). A match is not a finding of malicious intent.

A lightweight malware inspection engine with a web dashboard, always-on
real-time protection, quarantine, and a static analysis pipeline
(hashing, entropy, YARA, PE analysis, archive inspection, and a known-hash
reputation list).

## Features

- **Scan pipeline** — MD5/SHA1/SHA256 hashing, Shannon entropy, YARA matching,
  PE (Windows executable) analysis, string/IOC extraction, weighted scoring.
- **Reputation list** — instant verdicts for known-good/known-bad hashes.
- **Archive scanning** — looks inside `.zip/.tar/.jar` (zip-slip & zip-bomb safe).
- **Real-time protection** — watches Downloads/Desktop/Documents/Temp and scans
  new files as they arrive; optional auto-quarantine of malicious files.
- **Quarantine** — isolates threats (neutralized on disk), with restore/delete.
- **Web dashboard** — light, enterprise-style UI at `http://localhost:8888`.
- **Local security** — every command endpoint requires a per-machine access
  token (stored `0600`); loopback-only host check blocks DNS rebinding.

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

python main.py gui            :: full app: dashboard window + tray + protection
python main.py background     :: tray + real-time protection, no window
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
pip install pyinstaller
pyinstaller dexmond_mie.spec
```

This produces a one-folder build at `dist\DexmondMIE\`. Run
`dist\DexmondMIE\DexmondMIE.exe` to launch. Distribute the whole
`DexmondMIE` folder (or wrap it with an installer such as Inno Setup).

### Before shipping to production

- **Code-sign** `DexmondMIE.exe` with an Authenticode certificate — an unsigned
  security tool is aggressively flagged by SmartScreen and other AV.
- Add an application **icon** (`assets/dexmond.ico`, referenced in the `.spec`).
- Test the packaged build on a clean Windows VM (the window, tray, real-time
  protection, and quarantine paths have not yet been exercised on Windows).
- Consider an installer that sets **auto-start on login** if you want protection
  to run continuously.

## Testing safely

Use the standard **EICAR** test string (harmless, detected by every AV) to
verify detection without touching real malware.
