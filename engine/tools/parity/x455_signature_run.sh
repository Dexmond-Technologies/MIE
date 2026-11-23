#!/usr/bin/env bash
# The operator run on the corpus machine (x455), as the reviewer laid it out on 2026-11-23:
# before the comparison on real signed files, show on the same machine in the same session that
# the reference's signature check FAILS without the wrapper and WORKS with it, then run the
# comparison. An operator run, not CI: its header makes it evidence.
#
#   x455_signature_run.sh WORK_DIR ONE_MICROSOFT_FILE V1_FOLDER [V1_FOLDER ...]
#
#   WORK_DIR             where build_signature_probe.sh built everything (run it first, with
#                        PYTHON pointing at Python 3.12.16)
#   ONE_MICROSOFT_FILE   one Microsoft-signed program of v1 (normal files), for the before/after pair
#   V1_FOLDER            folders of v1 NORMAL files only: never B', never the 4 test files
#
# Run from the top of the MIE checkout at the commit to test. Writes only under WORK_DIR/run-<time>.
# Never prints file content; never opens trust/*.pem except to hash it (in the corpus script).
set -uo pipefail
WORK="$(cd "${1:?usage}" && pwd)"; MSFILE="${2:?usage}"; shift 2
[ "$#" -ge 1 ] || { echo "give at least one v1 folder" >&2; exit 2; }
REPO="$(pwd)"
VPY="$WORK/venv/bin/python"
PROBE="$WORK/build/mie-signature-probe"
LIBCRYPTO="$(ls "$WORK"/openssl-shared/x64-linux-dynamic/lib/libcrypto.so.3)"
LIBSSL="$(ls "$WORK"/openssl-shared/x64-linux-dynamic/lib/libssl.so.3)"
OUT="$WORK/run-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$OUT"
WRAP=("$VPY" "$REPO/engine/tools/parity/reference_with_openssl.py" --libcrypto "$LIBCRYPTO" --libssl "$LIBSSL")

{
echo "=== header"
echo "host: $(hostname)"; echo "date (UTC): $(date -u +%FT%TZ)"
echo "commit: $(git -C "$REPO" rev-parse HEAD); tree: $(git -C "$REPO" status --porcelain --untracked-files=no | wc -l) tracked files changed"
echo "compiler: $(c++ --version | head -1)"
echo "python: $("$VPY" --version)"
"$VPY" -m pip list --disable-pip-version-check 2>/dev/null | grep -i -E '^(signify|certvalidator|oscrypto|asn1crypto|mscerts) '
echo "system OpenSSL: $(openssl version 2>/dev/null)"
echo "probe: $PROBE sha256 $(sha256sum "$PROBE" | cut -d' ' -f1)"
echo "shared OpenSSL for the reference: $LIBCRYPTO sha256 $(sha256sum "$LIBCRYPTO" | cut -d' ' -f1)"

echo "=== 1. before/after on one Microsoft-signed v1 file (reviewer's addition)"
one="$OUT/one"; mkdir -p "$one"; cp "$MSFILE" "$one/$(sha256sum "$MSFILE" | cut -d' ' -f1)"
echo "--- WITHOUT the wrapper (the system OpenSSL):"
"$VPY" "$REPO/engine/tools/parity/signature_corpus_check.py" --folder "$one" --probe "$PROBE" --repo "$REPO" \
    --selection-rule "one Microsoft-signed v1 file, chosen by the operator" | grep -E 'reference:|^python|signature_corpus_check:'
echo "--- WITH the wrapper (shared OpenSSL 3.6.5):"
"${WRAP[@]}" "$REPO/engine/tools/parity/signature_corpus_check.py" --folder "$one" --probe "$PROBE" --repo "$REPO" \
    --selection-rule "one Microsoft-signed v1 file, chosen by the operator" | grep -E '^reference OpenSSL|reference:|signature_corpus_check:'

echo "=== 2. before/after on the generated cases (signature_parity; generated files only)"
"$VPY" -m pip install --quiet --disable-pip-version-check cryptography==50.0.2 yara-python==4.5.1 pefile==2024.8.26
echo "--- WITHOUT the wrapper:"
"$VPY" "$REPO/engine/tests/signature_parity.py" "$PROBE" "$REPO" > "$OUT/signature_parity-without.txt" 2>&1
echo "exit code $?"; grep -E 'valid_sha256|hard differences|signature_parity:' "$OUT/signature_parity-without.txt" | head -4
echo "--- WITH the wrapper:"
"${WRAP[@]}" "$REPO/engine/tests/signature_parity.py" "$PROBE" "$REPO" > "$OUT/signature_parity-with.txt" 2>&1
echo "exit code $?"; grep -E '^reference OpenSSL|PASS  valid_sha256|hard differences|signature_parity:' "$OUT/signature_parity-with.txt"
sha256sum "$OUT"/signature_parity-*.txt

echo "=== 3. selection (v1 normal files; rule independent of both checks)"
"$VPY" "$REPO/engine/tools/parity/select_signed_pe.py" $(for f in "$@"; do printf -- '--from %q ' "$f"; done) --to "$OUT/chosen"
} 2>&1 | tee "$OUT/part1.txt"

for profile in parity shipped; do
    "${WRAP[@]}" "$REPO/engine/tools/parity/signature_corpus_check.py" --folder "$OUT/chosen" --probe "$PROBE" \
        --repo "$REPO" --profile "$profile" \
        --selection-rule "PE files of v1 normal files with a non-empty certificate table, copied under their SHA-256 by select_signed_pe.py" \
        2>&1 | tee "$OUT/corpus-check-$profile.txt"
done
echo "=== records"; sha256sum "$OUT"/*.txt "$OUT/chosen.selection.tsv" | tee "$OUT/SHA256SUMS"
echo "Send back: the folder $OUT (logs only; NOT the chosen files) and SHA256SUMS."
