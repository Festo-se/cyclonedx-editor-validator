# Fuzzing with ClusterFuzzLite

This directory contains [Atheris](https://github.com/google/atheris) fuzz
targets that are run continuously by
[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) to harden the
untrusted-input parsing paths of `cdxev`.

## Fuzz targets

These fall into two groups: focused parser targets and end-to-end command targets.

### Parser-level targets

| Target | What it exercises |
| --- | --- |
| [fuzz_version_range.py](fuzz_version_range.py) | `version_is_in_version_range` → `univers` range/version parsing of untrusted `version-range` strings (highest-value surface) |
| [fuzz_sbom_filename.py](fuzz_sbom_filename.py) | JSON ingestion + `generate_filename` / `generate_validation_pattern`, incl. `dateutil` timestamp parsing |
| [fuzz_identity.py](fuzz_identity.py) | `ComponentIdentity.create` – purl/cpe/swid/coordinates key extraction and the non-transitive eq/hash logic |
| [fuzz_spec_version.py](fuzz_spec_version.py) | `SpecVersion.parse` – CycloneDX `specVersion` string parsing (lightweight smoke target) |

### End-to-end command targets

These build a *plausible* SBOM skeleton from the fuzzer bytes (via the shared
[_sbom_builder.py](_sbom_builder.py) helper) and run a whole command, so they
exercise real integration logic instead of drowning in expected validation
errors. **Every command exposed by the `cdx-ev` CLI has a target.**

| Command | Target | What it exercises |
| --- | --- | --- |
| `merge` | [fuzz_merge.py](fuzz_merge.py) | bom-ref unification, component-tree merge, dependency merge, vulnerability identity resolution |
| `amend` | [fuzz_amend.py](fuzz_amend.py) | default operations over the component tree (no network / arbitrary file I/O) |
| `set` | [fuzz_set.py](fuzz_set.py) | update-record validation (incl. `version-range` parsing), component mapping, property set/merge/delete |
| `vex` | [fuzz_vex.py](fuzz_vex.py) | the list/trim/search/extract sub-commands (CSV building, recursive `search_key`, id matching) |
| `list` | [fuzz_list.py](fuzz_list.py) | `cyclonedx-python-lib` `Bom.from_json` deserialization plus license/component extraction |
| `build-public-bom` | [fuzz_build_public_bom.py](fuzz_build_public_bom.py) | recursive internal-component removal and dependency fix-up |
| `validate` | [fuzz_validate.py](fuzz_validate.py) | full jsonschema pipeline (SPDX/JSF/crypto registries), custom error post-processing, filename-pattern validation |
| `init-sbom` | [fuzz_init_sbom.py](fuzz_init_sbom.py) | `email-validator` parsing of the untrusted email arg + free-text fields flowing into the CycloneDX model |

> The shared builder file is named `_sbom_builder.py` (leading underscore) so the
> build script does not try to compile it as a fuzzer; it is added to PYTHONPATH
> and bundled as a hidden import instead.

> `init-sbom` is the only command that does not consume an SBOM file; its target
> fuzzes the CLI string arguments directly (the `email` field is the notable
> third-party parsing surface).

Each file defines a `TestOneInput(data: bytes)` entry point (the name is
required by Atheris) and a `main()` that wires up `atheris.Setup` / `atheris.Fuzz`.

## How it runs in CI

The fuzzers are built and executed from the configuration in
[`.clusterfuzzlite/`](../../.clusterfuzzlite/) by the following workflows:

- `.github/workflows/cflite_pr.yml` – fuzzes code changed in a pull request.
- `.github/workflows/cflite_batch.yml` – longer batch fuzzing on `main` and nightly.
- `.github/workflows/cflite_cron.yml` – weekly corpus pruning and coverage report.

The corpus is stored in the GitHub Actions cache, so no extra storage repo or
secret is required.

## Running a fuzzer locally

Atheris only runs on Linux/macOS. With the package and `atheris` installed:

```bash
pip install atheris
pip install -e .
python tests/fuzz/fuzz_spec_version.py -atheris_runs=100000
```

To reproduce a crash reported by ClusterFuzzLite, pass the downloaded testcase
file as an argument:

```bash
python tests/fuzz/fuzz_spec_version.py ./crash-<hash>
```
