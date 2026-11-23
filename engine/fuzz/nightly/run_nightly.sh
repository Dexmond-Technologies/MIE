#!/usr/bin/env bash
# Nightly fuzzing of the MIE engine's fuzz targets on a cluster node (node4), one hour per target.
#
# Meets the reviewer's line "one hour per target" as amended on 2026-11-23 (board B-3551):
#   - starts by itself (systemd timer, see README.md in this folder);
#   - sanitizers on (AddressSanitizer + UndefinedBehaviorSanitizer, set in engine/CMakeLists.txt);
#   - one record per night and target: commit, target, runs, result, hash of the log;
#   - a missed or failed night is visible: the record of the night is FAILED or absent, and the
#     exit code is non-zero, so the timer unit is marked failed;
#   - a commit counts as fuzzed only with a record for that commit or a later one containing it.
#
# What it does: fetches branch cpp/stage1 into its own clone, builds the fuzz targets with clang
# from the pinned vcpkg commit, runs each target for FUZZ_SECONDS on its own core, saves the log,
# the corpus and any crash input, and appends one JSON line per target to records.jsonl.
#
# It needs: git, cmake, ninja or make, clang with libFuzzer (compiler-rt), curl, zip, unzip, tar,
# pkg-config, python3. It installs nothing and needs no root. It opens no network listener.
# Network use: git fetch from GitHub (the repository and vcpkg) and vcpkg's source downloads.
#
# Usage: run_nightly.sh            (configuration by environment, defaults below)
set -u

WORK="${MIE_FUZZ_WORK:-/mnt/node4-work/mie-fuzz}"
REPO_URL="${MIE_FUZZ_REPO:-https://github.com/Dexmond-Technologies/MIE.git}"
BRANCH="${MIE_FUZZ_BRANCH:-cpp/stage1}"
FUZZ_SECONDS="${MIE_FUZZ_SECONDS:-3600}"
RSS_LIMIT_MB="${MIE_FUZZ_RSS_MB:-2048}"
# Every fuzz target built by engine/CMakeLists.txt with -DMIE_FUZZ_ONLY=ON. Add new targets here.
TARGETS="${MIE_FUZZ_TARGETS:-fuzz_frame}"

case "$FUZZ_SECONDS" in ''|*[!0-9]*) echo "MIE_FUZZ_SECONDS must be a whole number" >&2; exit 2;; esac

NIGHT="$(date -u +%Y-%m-%d)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$WORK/runs/$STAMP"
RECORDS="$WORK/records.jsonl"
mkdir -p "$WORK" "$RUN_DIR" "$WORK/corpus" "$WORK/crashes" || { echo "cannot create $WORK" >&2; exit 2; }

# One run at a time.
exec 9>"$WORK/.lock"
if ! flock -n 9; then
    echo "another nightly run holds the lock" >&2
    exit 2
fi

record() {  # record <target> <result> <runs> <log file or ''> <detail>
    local target="$1" result="$2" runs="$3" log="$4" detail="$5" log_hash=""
    if [ -n "$log" ] && [ -f "$log" ]; then
        log_hash="$(sha256sum "$log" | cut -d' ' -f1)"
    fi
    python3 - "$RECORDS" "$NIGHT" "$STAMP" "${COMMIT:-unknown}" "$target" "$result" "$runs" \
        "$FUZZ_SECONDS" "$log" "$log_hash" "$detail" "$(hostname)" <<'PY'
import json, sys
path, night, stamp, commit, target, result, runs, seconds, log, log_hash, detail, host = sys.argv[1:13]
line = {"night": night, "started_utc": stamp, "commit": commit, "target": target, "result": result,
        "runs": int(runs) if runs.isdigit() else None, "seconds_asked": int(seconds),
        "log": log, "log_sha256": log_hash, "detail": detail, "host": host,
        "sanitizers": "address,undefined"}
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(line, sort_keys=True) + "\n")
print(json.dumps(line, sort_keys=True))
PY
}

fail_all() {  # the night failed before any target ran: one FAILED record per target
    local detail="$1" target
    for target in $TARGETS; do
        record "$target" "FAILED" "" "$RUN_DIR/build.log" "$detail"
    done
    exit 1
}

# ---- source: own clone, fetch only, never push --------------------------------------------
SRC="$WORK/src"
(
    if [ ! -d "$SRC/.git" ]; then
        git clone --quiet "$REPO_URL" "$SRC" || exit 1
    fi
    git -C "$SRC" fetch --quiet origin "$BRANCH" || exit 1
    git -C "$SRC" checkout --quiet --detach FETCH_HEAD || exit 1
) >"$RUN_DIR/build.log" 2>&1 || fail_all "cannot fetch the source"
COMMIT="$(git -C "$SRC" rev-parse HEAD)"

# ---- vcpkg at the commit the CI workflow pins ----------------------------------------------
VCPKG_COMMIT="$(sed -n 's/^ *VCPKG_COMMIT: *\([0-9a-f]\{40\}\).*/\1/p' "$SRC/.github/workflows/engine.yml" | head -1)"
[ -n "$VCPKG_COMMIT" ] || fail_all "no VCPKG_COMMIT in engine.yml"
VCPKG="$WORK/vcpkg-$VCPKG_COMMIT"
(
    if [ ! -x "$VCPKG/vcpkg" ]; then
        rm -rf "$VCPKG"
        git init --quiet "$VCPKG" &&
        git -C "$VCPKG" remote add origin https://github.com/microsoft/vcpkg &&
        git -C "$VCPKG" fetch --quiet --depth 1 origin "$VCPKG_COMMIT" &&
        git -C "$VCPKG" checkout --quiet FETCH_HEAD &&
        [ "$(git -C "$VCPKG" rev-parse HEAD)" = "$VCPKG_COMMIT" ] &&
        "$VCPKG/bootstrap-vcpkg.sh" -disableMetrics || exit 1
    fi
) >>"$RUN_DIR/build.log" 2>&1 || fail_all "cannot set up vcpkg at the pinned commit"

# ---- build the fuzz targets (clang, libFuzzer, sanitizers) ---------------------------------
BUILD="$WORK/build"
export CC=clang CXX=clang++ VCPKG_ROOT="$VCPKG" VCPKG_DISABLE_METRICS=1
export VCPKG_DEFAULT_BINARY_CACHE="$WORK/vcpkg-cache"
mkdir -p "$VCPKG_DEFAULT_BINARY_CACHE"
{
    rm -rf "$BUILD" &&
    cmake -S "$SRC/engine" -B "$BUILD" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DMIE_FUZZ_ONLY=ON \
          "-DCMAKE_TOOLCHAIN_FILE=$VCPKG/scripts/buildsystems/vcpkg.cmake" &&
    cmake --build "$BUILD" --parallel "$(nproc)"
} >>"$RUN_DIR/build.log" 2>&1 || fail_all "the fuzz targets did not build"

# ---- run every target for FUZZ_SECONDS, each on its own core, at the same time -------------
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
pids=""
for target in $TARGETS; do
    if [ ! -x "$BUILD/$target" ]; then
        record "$target" "FAILED" "" "$RUN_DIR/build.log" "target was not built"
        continue
    fi
    mkdir -p "$WORK/corpus/$target" "$RUN_DIR/$target-artifacts"
    (
        cd "$RUN_DIR" &&
        nice -n 10 "$BUILD/$target" -max_total_time="$FUZZ_SECONDS" -timeout=10 \
            -rss_limit_mb="$RSS_LIMIT_MB" -print_final_stats=1 \
            -artifact_prefix="$RUN_DIR/$target-artifacts/" "$WORK/corpus/$target" \
            >"$RUN_DIR/$target.log" 2>&1
        echo $? >"$RUN_DIR/$target.exit"
    ) &
    pids="$pids $!"
done
for pid in $pids; do wait "$pid"; done

# ---- one record per target ------------------------------------------------------------------
overall=0
for target in $TARGETS; do
    [ -f "$RUN_DIR/$target.exit" ] || { overall=1; continue; }
    code="$(cat "$RUN_DIR/$target.exit")"
    log="$RUN_DIR/$target.log"
    runs="$(sed -n 's/^stat::number_of_executed_units: *\([0-9]*\).*/\1/p' "$log" | tail -1)"
    found="$(find "$RUN_DIR/$target-artifacts" -type f | wc -l)"
    if [ "$code" = "0" ] && [ "$found" = "0" ] && [ -n "$runs" ]; then
        record "$target" "PASS" "$runs" "$log" "no crash, no sanitizer report, no input over the time limit"
    else
        overall=1
        if [ "$found" != "0" ]; then
            mkdir -p "$WORK/crashes/$STAMP-$target"
            cp -a "$RUN_DIR/$target-artifacts/." "$WORK/crashes/$STAMP-$target/"
        fi
        record "$target" "FAILED" "${runs:-}" "$log" "exit code $code, $found crash or timeout inputs saved under $WORK/crashes/$STAMP-$target"
    fi
done

# Keep the last 30 runs' logs; records.jsonl, corpus and crashes are never deleted here.
ls -1d "$WORK"/runs/*/ 2>/dev/null | sort | head -n -30 | while read -r old; do rm -rf "$old"; done

exit "$overall"
