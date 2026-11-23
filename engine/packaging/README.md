# `engine/packaging/` — Dexmond MIE Stage 1 Packaging (Windows & Linux)

Builds unsigned test installers and archives from the read-only `engine/` sources in
GitHub Actions (`.github/workflows/engine-pkg.yml`):

- **`wording.json`**: Single reviewable source for all user-facing installer, package,
  and `README.txt` lines.
- **`stage.py`**: Shared staging script (Windows and Linux). Builds `mie-service` and
  `mie` at the pinned `vcpkg` commit, collects required shared libraries (including
  app-local MSVC C++ runtime DLLs on Windows), generates `licenses/THIRD-PARTY-NOTICES.txt`
  and upstream licence files from `engine/third_party/pins.json`, and writes `README.txt`.
  Supports `--with-ui` / `WITH_UI=ON` (default `OFF`) for when `mie-ui` (Qt 6) merges.
- **`legal/`**: Draft LGPL-3.0, GPL-3.0, Qt LGPL notice, and three-year Qt source offer
  files (marked `DRAFT, not legal text` for legal review), staged when `WITH_UI=ON`.
- **`windows/mie.iss` & `build_windows_installer.py`**: Per-user (`%LOCALAPPDATA%\Programs\Dexmond MIE`)
  Inno Setup 6 installer with Start-menu shortcuts, optional `HKCU\...\Run` autostart,
  and clean service-stopping uninstaller.
- **`build_linux_packages.py`**: Builds the `.deb` (`/opt/dexmond-mie/`, `/usr/bin/mie`
  wrapper, `/etc/xdg/autostart/dexmond-mie-service.desktop`) for Debian 13 and Ubuntu LTS,
  the `.tar.gz` archive, and `SHA256SUMS`.
- **`test_windows_pkg.py` & `test_linux_pkg.py`**: CI acceptance tests `P-1`–`P-9` and
  `L-1`–`L-8` (including inside a `debian:13` container).

## Signing Placeholders (empty in test builds)

- Windows Authenticode: `MIE_WIN_CODESIGN_CERT`, `MIE_WIN_CODESIGN_TIMESTAMP_URL`
- Linux `SHA256SUMS` GPG signature: `MIE_LINUX_GPG_KEY_ID`

When empty, signing steps are skipped with an explicit log line and packages are marked
`UNSIGNED TEST BUILD` / `UNSIGNED-TEST-BUILD`.
