#!/usr/bin/env bash
# Builds mie-signature-probe and the Python environment that signature_corpus_check.py needs, on a
# Linux machine without root (the corpus machine). The same script runs in CI on Ubuntu 24.04 with
# its own gcc and Python (job signature-recipe), so the recipe is tested before anyone runs it.
#
#   build_signature_probe.sh WORK_DIR
#
# Run from the top of a checkout of the MIE repository at the commit to test. It needs: git,
# cmake (3.25 or newer), a C++20 compiler (gcc 13 or newer), make or ninja, curl, zip, unzip, tar,
# pkg-config, python3 with the venv module; network access to github.com (vcpkg and its source
# downloads) and to the Python package index. It writes only under WORK_DIR and never opens,
# prints or copies trust/*.pem, keys or corpus files.
# At the end it prints the probe's path and SHA-256 and the venv's Python.
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

[ -x "$WORK/venv/bin/python" ] || python3 -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install --quiet --disable-pip-version-check --require-hashes \
    -r "$REPO/requirements-signify.lock"

echo "commit:  $(git -C "$REPO" rev-parse HEAD)"
echo "compiler: $(c++ --version | head -1)"
echo "python:  $("$WORK/venv/bin/python" --version)"
echo "probe:   $WORK/build/mie-signature-probe"
echo "sha256:  $(sha256sum "$WORK/build/mie-signature-probe" | cut -d' ' -f1)"
