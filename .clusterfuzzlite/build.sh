#!/bin/bash -eu
# SPDX-License-Identifier: GPL-3.0-or-later
# Build script for ClusterFuzzLite. Installs the package and compiles every
# fuzz_*.py target found under tests/fuzz into a self-contained fuzzer.

# Install the project and its runtime dependencies into the fuzzing image so the
# fuzz targets can import cdxev. Dependencies are installed from a hash-pinned
# requirements file (generated from uv.lock) so the build is reproducible and
# satisfies Scorecard's pinned-dependencies check. Regenerate it with:
#   uv export --frozen --no-default-groups --no-emit-project \
#     --format requirements-txt -o .clusterfuzzlite/requirements.txt
pip3 install --no-cache-dir --require-hashes -r .clusterfuzzlite/requirements.txt

# Install cdxev itself from the local checkout without re-resolving dependencies
# (they are already pinned above). An editable install keeps the package pinned
# to local source, which Scorecard recognizes as a pinned dependency.
pip3 install --no-cache-dir --no-deps -e .

# The command-level fuzzers import the shared `_sbom_builder` helper that lives
# next to them. Put that directory on PYTHONPATH so both runtime imports and the
# PyInstaller analysis performed by compile_python_fuzzer can resolve it.
REPO_DIR="$SRC/cyclonedx-editor-validator"
FUZZ_DIR="$REPO_DIR/tests/fuzz"
export PYTHONPATH="$FUZZ_DIR:${PYTHONPATH:-}"

# cdxev loads several data files at runtime via importlib.resources. PyInstaller
# only bundles Python modules, so these JSON resources must be added explicitly,
# preserving their package directory layout so importlib.resources can find them.
DATA_ARGS=(
  "--add-data=$REPO_DIR/cdxev/amend/license_name_spdx_id_map.json:cdxev/amend"
  "--add-data=$REPO_DIR/cdxev/auxiliary/schema:cdxev/auxiliary/schema"
  "--copy-metadata=cyclonedx-editor-validator"
)

# Compile each fuzz target. compile_python_fuzzer packages the target together
# with its dependencies using PyInstaller and wires up Atheris coverage.
# `_sbom_builder` is added as a hidden import so PyInstaller bundles it even
# though it's only imported dynamically after a sys.path tweak.
for fuzzer in "$FUZZ_DIR/"fuzz_*.py; do
  compile_python_fuzzer "$fuzzer" --hidden-import=_sbom_builder "${DATA_ARGS[@]}"
done
