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
# Then (part 2) it builds the engine's probes and runs the parity tests of the executable
# reader, its analysis and the zip/tar readers against the Python reference on at least 200,000
# damaged variants each, with a new seed each night, and appends one JSON line per test. Part 2
# stops cleanly at a wall-clock deadline (default 02:45 UTC): a test stopped there is recorded
# INCOMPLETE with the number of variants it compared.
#
# It needs: git, cmake, ninja or make, clang with libFuzzer (compiler-rt), a C++ compiler for the
# normal build, curl, zip, unzip, tar, pkg-config, python3 with the venv module. It needs no root
# and opens no network listener. The only things it installs are Python packages into its own
# virtual environment under the work folder (pefile 2024.8.26 and yara-python 4.5.1; the archive
# test needs yara-python because it builds the reference's own engine).
# Network use: git fetch from GitHub (the repository and vcpkg), vcpkg's source downloads, and,
# the first time, the Python package index for that virtual environment.
#
# Usage: run_nightly.sh            (configuration by environment, defaults below)
set -u

WORK="${MIE_FUZZ_WORK:-/mnt/node4-work/mie-fuzz}"
REPO_URL="${MIE_FUZZ_REPO:-https://github.com/Dexmond-Technologies/MIE.git}"
BRANCH="${MIE_FUZZ_BRANCH:-cpp/stage1}"
FUZZ_SECONDS="${MIE_FUZZ_SECONDS:-3600}"
RSS_LIMIT_MB="${MIE_FUZZ_RSS_MB:-2048}"
# Every fuzz target built by engine/CMakeLists.txt with -DMIE_FUZZ_ONLY=ON. Add new targets here.
TARGETS="${MIE_FUZZ_TARGETS:-fuzz_frame fuzz_pe fuzz_zip fuzz_tar fuzz_signature}"
# Second part of the night: the parity tests of the executable reader and of its analysis
# against the Python reference, on far more damaged variants than a push runs (reviewer, board
# B-3620: at least 200,000 per night). Set MIE_PARITY_TESTS to an empty value to leave it out.
# The archive readers were added by the reviewer's conditions before gate 3 (board B-3628).
PARITY_TESTS="${MIE_PARITY_TESTS-pe_parity pe_analysis_parity archive_parity}"
PARITY_TOTAL="${MIE_PE_TOTAL_VARIANTS:-200000}"
PARITY_SEED="${MIE_PE_SEED:-$(date -u +%Y%m%d)}"     # a new seed every night, written in the log
# Wall-clock deadline of part 2, HH:MM in UTC: the next such time after the start of the run.
# Empty: no deadline. (COMMANDER_SEAT's choice for node4: start 21:30 UTC, deadline 02:45 UTC.)
PARITY_DEADLINE_UTC="${MIE_PARITY_DEADLINE_UTC-02:45}"
START_UNIX="$(date -u +%s)"
PARITY_DEADLINE_UNIX=0
if [ -n "$PARITY_DEADLINE_UTC" ]; then
    PARITY_DEADLINE_UNIX="$(date -u -d "$(date -u +%F) $PARITY_DEADLINE_UTC" +%s)" || {
        echo "MIE_PARITY_DEADLINE_UTC must be HH:MM" >&2; exit 2; }
    if [ "$PARITY_DEADLINE_UNIX" -le "$START_UNIX" ]; then
        PARITY_DEADLINE_UNIX=$((PARITY_DEADLINE_UNIX + 86400))
    fi
fi

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

record() {  # record <target> <result> <runs> <log file or ''> <detail> [kind: fuzz (default) or parity]
    local target="$1" result="$2" runs="$3" log="$4" detail="$5" kind="${6:-fuzz}" log_hash=""
    if [ -n "$log" ] && [ -f "$log" ]; then
        log_hash="$(sha256sum "$log" | cut -d' ' -f1)"
    fi
    python3 - "$RECORDS" "$NIGHT" "$STAMP" "${COMMIT:-unknown}" "$target" "$result" "$runs" \
        "$FUZZ_SECONDS" "$log" "$log_hash" "$detail" "$(hostname)" "$kind" "$PARITY_SEED" <<'PY'
import json, sys
(path, night, stamp, commit, target, result, runs, seconds, log, log_hash, detail, host, kind,
 seed) = sys.argv[1:15]
line = {"night": night, "started_utc": stamp, "commit": commit, "target": target, "result": result,
        "runs": int(runs) if runs.isdigit() else None, "log": log, "log_sha256": log_hash,
        "detail": detail, "host": host, "kind": kind}
if kind == "parity":    # runs = damaged variants compared with the Python reference
    line.update({"seconds_asked": None, "sanitizers": "none (release build)", "seed": seed})
else:                   # runs = inputs the fuzzer executed
    line.update({"seconds_asked": int(seconds), "sanitizers": "address,undefined"})
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
    for target in $PARITY_TESTS; do
        record "$target" "FAILED" "" "$RUN_DIR/build.log" "$detail" parity
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

# ---- part 2: parity of the executable reader and its analysis with the Python reference ----
# Needs a Python with pefile 2024.8.26 (the reference's parser library). It is kept in a
# virtual environment under the work folder, created once; creating it needs network access
# to the Python package index. yara-python 4.5.1 is installed too when it can be (the two
# tests below do not use it; a failure to install it is written to the log and is not fatal).
if [ -n "$PARITY_TESTS" ]; then
    VENV="$WORK/venv"
    BUILD_ENGINE="$WORK/build-engine"
    parity_ready=1
    (
        if [ ! -x "$VENV/bin/python" ]; then
            python3 -m venv "$VENV" || exit 1
        fi
        "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check "pefile==2024.8.26" || exit 1
        rm -f "$RUN_DIR/no-yara"
        "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check "yara-python==4.5.1" || {
            echo "yara-python 4.5.1 could not be installed for this Python: the archive test cannot run"
            : >"$RUN_DIR/no-yara"; }
        "$VENV/bin/python" --version
        "$VENV/bin/python" -m pip list --disable-pip-version-check 2>/dev/null | grep -i -E '^(pefile|yara-python) '
        # The fuzz targets above are built with clang; this build uses the system's default
        # compiler, as the GitHub Linux job does (warnings are errors, and only that compiler
        # and MSVC have been seen to build every file clean).
        unset CC CXX
        rm -rf "$BUILD_ENGINE" &&
        cmake -S "$SRC/engine" -B "$BUILD_ENGINE" -DCMAKE_BUILD_TYPE=Release -DMIE_BUILD_TESTS=OFF \
              "-DCMAKE_TOOLCHAIN_FILE=$VCPKG/scripts/buildsystems/vcpkg.cmake" &&
        cmake --build "$BUILD_ENGINE" --parallel "$(nproc)" --target mie-pe-probe mie-pe-analysis-probe mie-archive-probe
    ) >"$RUN_DIR/parity-build.log" 2>&1 || parity_ready=0

    if [ "$parity_ready" = "0" ]; then
        overall=1
        for test in $PARITY_TESTS; do
            record "$test" "FAILED" "" "$RUN_DIR/parity-build.log" "the Python environment or the engine build failed" parity
        done
    else
        pids=""
        for test in $PARITY_TESTS; do
            case "$test" in
                pe_parity) probe="mie-pe-probe" ;;
                pe_analysis_parity) probe="mie-pe-analysis-probe" ;;
                archive_parity) probe="mie-archive-probe" ;;
                *) probe="" ;;
            esac
            if [ "$test" = "archive_parity" ] && [ -e "$RUN_DIR/no-yara" ]; then
                echo "yara-python 4.5.1 is not installed: the archive test needs it" >"$RUN_DIR/$test.log"
                echo 2 >"$RUN_DIR/$test.exit"
                continue
            fi
            if [ -z "$probe" ] || [ ! -x "$BUILD_ENGINE/$probe" ]; then
                echo "no probe for $test" >"$RUN_DIR/$test.log"
                echo 2 >"$RUN_DIR/$test.exit"
                continue
            fi
            (
                MIE_PE_TOTAL_VARIANTS="$PARITY_TOTAL" MIE_PE_SEED="$PARITY_SEED" \
                MIE_ARCHIVE_VARIANTS="$PARITY_TOTAL" MIE_ARCHIVE_SEED="$PARITY_SEED" \
                MIE_PARITY_DEADLINE_UNIX="$PARITY_DEADLINE_UNIX" nice -n 10 \
                    "$VENV/bin/python" "$SRC/engine/tests/$test.py" "$BUILD_ENGINE/$probe" "$SRC" \
                    >"$RUN_DIR/$test.log" 2>&1
                echo $? >"$RUN_DIR/$test.exit"
            ) &
            pids="$pids $!"
        done
        for pid in $pids; do wait "$pid"; done
        for test in $PARITY_TESTS; do
            code="$(cat "$RUN_DIR/$test.exit" 2>/dev/null || echo missing)"
            log="$RUN_DIR/$test.log"
            # The count of damaged variants actually compared (every test prints this line).
            variants="$(sed -n "s/^$test: compared \([0-9][0-9]*\) damaged variants.*/\1/p" "$log" | tail -1)"
            last="$(grep -E "^$test: [0-9]+ differences" "$log" | tail -1)"
            if [ "$code" = "0" ] && [ -n "$variants" ] && [ "$variants" -ge "$PARITY_TOTAL" ]; then
                record "$test" "PASS" "$variants" "$log" "seed $PARITY_SEED; $last" parity
            elif [ "$code" = "3" ]; then
                overall=1
                record "$test" "INCOMPLETE" "${variants:-0}" "$log" "seed $PARITY_SEED; $last; stopped at the deadline $PARITY_DEADLINE_UTC UTC after ${variants:-0} damaged variants; at least $PARITY_TOTAL are required" parity
            else
                overall=1
                record "$test" "FAILED" "${variants:-}" "$log" "seed $PARITY_SEED; exit code $code; ${last:-no result line}; at least $PARITY_TOTAL variants are required" parity
            fi
        done
    fi
fi

# Keep the last 30 runs' logs; records.jsonl, corpus and crashes are never deleted here.
ls -1d "$WORK"/runs/*/ 2>/dev/null | sort | head -n -30 | while read -r old; do rm -rf "$old"; done

exit "$overall"
