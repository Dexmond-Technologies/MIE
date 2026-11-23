#!/usr/bin/env bash
# Says, for one night, whether every fuzz target and every nightly parity test has a PASS record: the line the coordinator
# posts on the board. A night with no record at all is MISSED, which counts as not met.
#
# Usage: check_night.sh [YYYY-MM-DD]     (default: today's date in UTC)
# Exit code: 0 every target PASS, 1 any FAILED, 3 any MISSED.
set -u
WORK="${MIE_FUZZ_WORK:-/mnt/node4-work/mie-fuzz}"
TARGETS="${MIE_FUZZ_TARGETS:-fuzz_frame fuzz_pe fuzz_zip fuzz_tar} ${MIE_PARITY_TESTS-pe_parity pe_analysis_parity}"
NIGHT="${1:-$(date -u +%Y-%m-%d)}"
python3 - "$WORK/records.jsonl" "$NIGHT" $TARGETS <<'PY'
import json, os, sys
path, night, targets = sys.argv[1], sys.argv[2], sys.argv[3:]
records = []
if os.path.exists(path):
    with open(path, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
worst = 0
for target in targets:
    mine = [r for r in records if r.get("night") == night and r.get("target") == target]
    if not mine:
        print(f"{night} {target}: MISSED (no record)")
        worst = max(worst, 3)
        continue
    last = mine[-1]
    amount = (f"variants {last['runs']} seed {last.get('seed')}" if last.get("kind") == "parity"
              else f"runs {last['runs']} seconds {last.get('seconds_asked')}")
    print(f"{night} {target}: {last['result']} commit {last['commit'][:12]} {amount} "
          f"log sha256 {last['log_sha256'][:16]} {last['detail']}")
    if last["result"] != "PASS":
        worst = max(worst, 1)
sys.exit(worst)
PY
