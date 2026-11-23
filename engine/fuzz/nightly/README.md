# Nightly fuzzing on a cluster node

GitHub Actions fuzzes every push for 60 seconds per target. The reviewer's line is one hour per
target; it is met by this nightly job on node4 (coordinator's decision and reviewer's agreement,
2026-11-23, board B-3551), which costs no Actions minutes.

Status: WRITTEN, NOT YET RUN. The line counts as met only from the first PASS record on.

## What runs

`run_nightly.sh` fetches branch `cpp/stage1` into its own clone (fetch only, it never pushes),
builds the fuzz targets with clang, libFuzzer, AddressSanitizer and UndefinedBehaviorSanitizer
from the vcpkg commit that `.github/workflows/engine.yml` pins, and runs every target for one
hour, each on its own core, all at the same time.

Targets today: `fuzz_frame` (the channel frame decoder) and `fuzz_pe` (the reader for Windows
executables). Planned with the engine: the archive reader.

## Second part of the night: parity on 200,000 damaged executables and archives

Since 2026-11-23 the archive readers are part of it too (`engine/tests/archive_parity.py`,
at least 200,000 damaged archives, `MIE_ARCHIVE_VARIANTS`; reviewer's conditions before gate 3,
board B-3628); it needs `yara-python==4.5.1` because it builds the reference's own engine.
Part 2 stops cleanly at a wall-clock deadline, `MIE_PARITY_DEADLINE_UTC` (default `02:45`, the
next such time after the start; empty for none): no new batch is started after it, and a test
stopped there is recorded `INCOMPLETE` with the number of damaged variants it compared
(COMMANDER_SEAT's choice for node4: timer at 21:30 UTC, deadline 02:45 UTC).

After the fuzzing the same script builds the engine's two executable probes (normal build,
system compiler, same pinned vcpkg) and runs `engine/tests/pe_parity.py` and
`engine/tests/pe_analysis_parity.py`, the tests every push runs with 100 damaged variants per
base file, with at least 200,000 variants in all (reviewer, board B-3620) and a seed taken from
the date, so every night tries different damage. The seed is in the log and in the record, so
any night can be repeated: `MIE_PE_SEED=<seed> MIE_PE_TOTAL_VARIANTS=200000 python
engine/tests/pe_parity.py <probe> <repository>`.

The reference side needs Python with `pefile==2024.8.26`. The script keeps a virtual
environment for it under the work folder (`venv/`), created the first time; that first time
needs network access to the Python package index. `yara-python==4.5.1` is installed there too
when the node's Python has a build of it; these two tests do not use it.

A record of kind `parity` has `runs` = damaged variants compared, `seed`, and the test's last
line in `detail`. PASS needs exit code 0 AND at least the required number of variants.
How long 200,000 variants take on the node: NOT MEASURED. A new target is added to `TARGETS` in the script and in the
`CPUQuota` of the unit.

## What it leaves, under `/mnt/node4-work/mie-fuzz/`

| Path | Content |
|---|---|
| `records.jsonl` | one line per night and target: night, start time, commit, target, result (PASS or FAILED), runs, seconds asked, log path, SHA-256 of the log, detail, host. Never rewritten, only appended |
| `runs/<start time>/` | build log, one log per target; the last 30 nights are kept |
| `corpus/<target>/` | the growing corpus, kept between nights |
| `crashes/<start time>-<target>/` | every crash, sanitizer or time-limit input, kept for ever |

Exit code: 0 only if every target ended with no crash, no sanitizer report and no input over the
time limit; non-zero otherwise, so the systemd unit shows as failed.

A commit counts as fuzzed only if `records.jsonl` holds a PASS record for that commit or for a
later commit that contains it.

## Missed or failed nights

`check_night.sh [date]` prints one line per fuzz target and per parity test for a night: PASS,
FAILED or MISSED (no record). The board lives on the coordinator's machine, not on the node, so the posting of a
missed or failed night is done by the coordinator from this line; the job itself cannot post.

## Resources

- Cores: one per target while fuzzing (two targets today); then one per parity test (two) for the
  second part;
  the build before it uses all cores for a few minutes (first night longer: OpenSSL and Catch2
  are built once from source and then cached under `vcpkg-cache/`).
- Memory: at most 2 GiB per target (libFuzzer's limit, `-rss_limit_mb=2048`); the unit caps the
  whole job at 6 GiB.
- Disk: the vcpkg checkout and cache, the build tree, logs and corpus; size NOT MEASURED.
- Time: starts 00:30, one hour of fuzzing plus the build; clear of 03:00 to 05:00.
- Network: outgoing only (git fetch of the repository and of vcpkg, vcpkg's source downloads).
  A private repository needs the node's own read access to GitHub.
- Needs on the node, none installed by the job: git, cmake, a build tool, clang with libFuzzer
  (compiler-rt), python3, curl, zip, unzip, tar, pkg-config, flock.

## Install (as the node's normal user, no root)

    mkdir -p ~/mie-fuzz ~/.config/systemd/user
    cp run_nightly.sh check_night.sh ~/mie-fuzz/
    cp mie-fuzz.service mie-fuzz.timer ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now mie-fuzz.timer
    loginctl enable-linger "$USER"     # so the timer runs without a login session (needs the node's admin once)

The 24 hours per target before a release candidate: `MIE_FUZZ_SECONDS=86400 ~/mie-fuzz/run_nightly.sh`,
started by hand under a slot.
