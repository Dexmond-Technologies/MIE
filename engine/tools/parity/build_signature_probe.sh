#!/usr/bin/env bash
# Builds mie-signature-probe and the Python environment that signature_corpus_check.py needs, on a
# Linux machine without root (the corpus machine). The same script runs in CI on Ubuntu 24.04 with
# its own gcc and Python (job signature-recipe), so the recipe is tested before anyone runs it.
#
#   [PYTHON=/path/to/python3.12.16] build_signature_probe.sh WORK_DIR
#
# The reviewer requires Python 3.12.16 for the reference side (ruling on gate 3, 2026-11-23). If the
# system's python3 is another version, give a 3.12.16 interpreter in PYTHON; without root it can be
# had for example with `uv python install 3.12.16` (then PYTHON="$(uv python find 3.12.16)").
# The script refuses any other version unless MIE_ALLOW_OTHER_PYTHON=1 (then it says so).
#
# Run from the top of a checkout of the MIE repository at the commit to test. It needs: git,
# cmake (3.25 or newer), a C++20 compiler (gcc 13 or newer), make or ninja, curl, zip, unzip, tar,
# pkg-config, python3 with the venv module; network access to github.com (vcpkg and its source
# downloads) and to the Python package index. It writes only under WORK_DIR and never opens,
# prints or copies trust/*.pem, keys or corpus files.
# At the end it prints the probe's path and SHA-256, the venv's Python, and the shared OpenSSL
# libraries for the reference (path and SHA-256).
set -euo pipefail
WORK="${1:?usage: build_signature_probe.sh WORK_DIR}"
REPO="$(pwd)"
VCPKG_COMMIT=9eec002df1cd109f8f104cd966a763daf9751489     # the pin of .github/workflows/engine.yml
test -f "$REPO/engine/CMakeLists.txt" || { echo "run this from the top of the MIE checkout" >&2; exit 2; }
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

if [ ! -d "$WORK/vcpkg/.git" ]; then
    git init --quiet "$WORK/vcpkg"
    git -C "$WORK/vcpkg" remote add origin https://github.com/microsoft/vcpkg
fi
git -C "$WORK/vcpkg" fetch --quiet --depth 1 origin "$VCPKG_COMMIT"
git -C "$WORK/vcpkg" checkout --quiet FETCH_HEAD
test "$(git -C "$WORK/vcpkg" rev-parse HEAD)" = "$VCPKG_COMMIT"
[ -x "$WORK/vcpkg/vcpkg" ] || "$WORK/vcpkg/bootstrap-vcpkg.sh" -disableMetrics

cmake -S "$REPO/engine" -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release -DMIE_BUILD_TESTS=OFF \
      "-DCMAKE_TOOLCHAIN_FILE=$WORK/vcpkg/scripts/buildsystems/vcpkg.cmake"
cmake --build "$WORK/build" --parallel "$(nproc)" --target mie-signature-probe

# A SHARED build of the OpenSSL the engine uses (3.6.5, same vcpkg commit) for the reference's
# oscrypto (reviewer's ruling, option b): see reference_with_openssl.py.
"$WORK/vcpkg/vcpkg" install openssl --classic --triplet x64-linux-dynamic \
    --x-install-root="$WORK/openssl-shared" --disable-metrics
LIBCRYPTO="$(ls "$WORK"/openssl-shared/x64-linux-dynamic/lib/libcrypto.so.3)"
LIBSSL="$(ls "$WORK"/openssl-shared/x64-linux-dynamic/lib/libssl.so.3)"

PY="${PYTHON:-python3}"
version="$("$PY" -c 'import platform; print(platform.python_version())')"
if [ "$version" != "3.12.16" ]; then
    if [ "${MIE_ALLOW_OTHER_PYTHON:-0}" = "1" ]; then
        echo "WARNING: Python $version, not 3.12.16 (MIE_ALLOW_OTHER_PYTHON=1): not valid for the reviewer's run"
    else
        echo "Python $version found; 3.12.16 is required (set PYTHON, see the head of this script)" >&2
        exit 2
    fi
fi
[ -x "$WORK/venv/bin/python" ] || "$PY" -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install --quiet --disable-pip-version-check --require-hashes \
    -r "$REPO/requirements-signify.lock"

echo "commit:  $(git -C "$REPO" rev-parse HEAD)"
echo "compiler: $(c++ --version | head -1)"
echo "python:  $("$WORK/venv/bin/python" --version)"
echo "probe:   $WORK/build/mie-signature-probe"
echo "sha256:  $(sha256sum "$WORK/build/mie-signature-probe" | cut -d' ' -f1)"
echo "libcrypto: $LIBCRYPTO sha256 $(sha256sum "$LIBCRYPTO" | cut -d' ' -f1)"
echo "libssl:    $LIBSSL sha256 $(sha256sum "$LIBSSL" | cut -d' ' -f1)"
echo "openssl port in vcpkg: $(grep -m1 '"version' "$WORK/vcpkg/ports/openssl/vcpkg.json")"
