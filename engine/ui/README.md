# engine/ui/ : Dexmond MIE stage 1 window and tray (`mie-ui`)

`mie-ui` is the thin C++20 / Qt 6 Widgets desktop window and system-tray front end for
`mie-service`. It never reads, opens, hashes, parses or judges any scanned file itself; it
speaks exclusively over the protocol version 1 local channel (`engine/docs/INTERFACES.md`)
using the read-only client code in `../include/mie/channel/` and `../src/channel/`, and parses
scan results exclusively through `mie::from_json` (`../src/core/result.cpp`).

## Pinned Qt 6 version and origin

- **Exact version:** `6.8.3` (the newest open-source LGPLv3 patch release of the Qt 6.8 LTS
  branch available for unattended installation on both Linux and Windows; later 6.8.x patch
  releases are commercial-only).
- **Where it comes from:** Official prebuilt dynamic binaries published by The Qt Company on
  `https://download.qt.io/online/qtsdkrepository/`, fetched in GitHub Actions via pinned
  `aqtinstall==3.3.0`:
  - Ubuntu (`ubuntu-latest`): `linux desktop 6.8.3 linux_gcc_64` (`6.8.3/gcc_64`)
  - Windows (`windows-latest`): `windows desktop 6.8.3 win64_msvc2022_64` (`6.8.3/msvc2022_64`)
- **Modules and licensing:** Used under GNU LGPL version 3, linked **dynamically** as separate
  shared libraries against **`Qt6::Core`**, **`Qt6::Gui`**, and **`Qt6::Widgets` only** (never
  static Qt, never `QtNetwork`, `Qml`/`Quick`, `WebEngine`, `Charts`, or any GPL-only module).
  Note on Linux ELF transitive dependencies: `mie-ui`'s own ELF `DT_NEEDED` table links only
  `libQt6Core.so.6`, `libQt6Gui.so.6`, and `libQt6Widgets.so.6`; `ldd` additionally shows
  `libQt6DBus.so.6` because Qt's prebuilt Linux `libQt6Gui.so.6` itself depends on it for XDG /
  StatusNotifier desktop integration. `T-11` verifies both `readelf -d` and `ldd` on Linux and
  `dumpbin /dependents` on Windows.

## Other dependencies

- `nlohmann-json`: obtained from the exact same pinned `vcpkg` commit
  (`9eec002df1cd109f8f104cd966a763daf9751489`) as `.github/workflows/engine.yml`, through
  `engine/ui/vcpkg.json`.

## Source layout

- `src/ui_strings.hpp`, `src/ui_strings.cpp`: the **single** source file containing every
  user-facing string in `mie-ui` (audited by acceptance test `T-8`).
- `src/text_sanitize.hpp`, `src/text_sanitize.cpp`: plain-text sanitization for hostile text
  arriving from the service or scanned files (control characters and Unicode bidirectional /
  format overrides replaced with visible `[U+XXXX]` markers, invalid UTF-8 replaced, long strings
  cut for display).
- `src/service_client.hpp`, `src/service_client.cpp`: dedicated worker-thread client so blocking
  channel calls never run on the GUI thread.
- `src/main_window.hpp`, `src/main_window.cpp`: main window (State, Scan a file, Quarantine,
  Trusted files, About and limits), tray icon/menu controller, and `QSettings` window geometry
  persistence.
- `src/main.cpp`: entry point supporting `--endpoint NAME`.
- `tests/`: Qt Test headless acceptance suite (`QT_QPA_PLATFORM=offscreen`) covering `T-1`
  through `T-14`, fake protocol-v1 service, raw malformed-frame server, and ASan/UBSan support.

## Building and testing

Builds and tests run in GitHub Actions (`.github/workflows/engine-qt.yml`) on `ubuntu-latest`
(Release and Debug+ASan+UBSan) and `windows-latest` (Release).
