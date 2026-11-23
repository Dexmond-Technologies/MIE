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

Targets today: `fuzz_frame` (the channel frame decoder). Planned with the engine: the executable
parser and the archive reader. A new target is added to `TARGETS` in the script and in the
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

`check_night.sh [date]` prints one line per target for a night: PASS, FAILED or MISSED (no
record). The board lives on the coordinator's machine, not on the node, so the posting of a
missed or failed night is done by the coordinator from this line; the job itself cannot post.

## Resources

- Cores: one per target while fuzzing (today 1; 3 when the parser and archive targets exist);
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
