# SPDX-License-Identifier: GPL-3.0-or-later
# Dockerfile for ClusterFuzzLite fuzzing of cyclonedx-editor-validator.
# Uses the OSS-Fuzz Python base builder which ships Atheris and the
# compile_python_fuzzer helper.
FROM gcr.io/oss-fuzz-base/base-builder-python

# Copy the whole repository into $SRC so build.sh can install it.
COPY . $SRC/cyclonedx-editor-validator

WORKDIR $SRC/cyclonedx-editor-validator

COPY .clusterfuzzlite/build.sh $SRC/build.sh
