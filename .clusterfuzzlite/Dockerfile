# SPDX-License-Identifier: GPL-3.0-or-later
# Dockerfile for ClusterFuzzLite fuzzing of cyclonedx-editor-validator.
# Uses the OSS-Fuzz Python base builder which ships Atheris and the
# compile_python_fuzzer helper.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:952a33b91674f2848d3099bb1a7f464143f61995e41f8cf5119c735c7607b495

# PyICU (a transitive dependency) is a C extension that needs the ICU
# development libraries and pkg-config to build its wheel.
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libicu-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the whole repository into $SRC so build.sh can install it.
COPY . $SRC/cyclonedx-editor-validator

WORKDIR $SRC/cyclonedx-editor-validator

COPY .clusterfuzzlite/build.sh $SRC/build.sh
