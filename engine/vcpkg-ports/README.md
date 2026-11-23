# engine/vcpkg-ports: build recipes of our own

Only for libraries whose version must differ from the one in the pinned vcpkg commit.

## yara (4.5.1)

The reviewer's condition M-5: the rules engine is the exact YARA version inside the
reference's `yara-python 4.5.1`. CI records that version on every run (job parity-tools,
"yara_library": "4.5.1"). The pinned vcpkg commit carries YARA 4.5.8, so this folder holds
a copy of vcpkg's own recipe for YARA (from vcpkg commit 9eec002df1cd109f8f104cd966a763daf9751489,
files `CMakeLists.txt`, `Disable-module-elf.patch`, `portfile.cmake`, `vcpkg.json`; vcpkg is
MIT-licensed) with two changes: the version (4.5.1) and the SHA-512 of the 4.5.1 source archive.

The recipe leaves the `elf` module out (as vcpkg's does). The reference's rules use no
module at all (only strings, `uint16(0)` and `filesize`), so this does not change a match;
`engine/tests/rules_parity.py` compares the matches with yara-python on every push.

Used by: `-DVCPKG_OVERLAY_PORTS=<repo>/engine/vcpkg-ports` together with the manifest
feature `rules`.

A newer YARA is NOT taken silently, even for a security fix: a fix to 4.5.1 is a recorded
patch here and goes to the reviewer first, because it can touch parity.
