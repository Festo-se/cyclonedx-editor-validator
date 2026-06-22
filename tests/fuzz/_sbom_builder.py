# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared helpers for the end-to-end (command-level) fuzz targets.

The command fuzzers don't throw completely random bytes at the commands -- that
would just produce a flood of expected ``AppError`` / ``KeyError`` noise. Instead
they build a *plausible* CycloneDX SBOM skeleton from the fuzzer-controlled bytes
so that execution gets past the trivial structural guards and actually exercises
the interesting logic (identity resolution, bom-ref unification, version-range
matching, component-tree walking, vulnerability merging).

``build_sbom`` is intentionally biased towards well-formed-but-adversarial input:
real field names, occasional missing/duplicate/oversized values, controlled
nesting depth and list sizes.
"""

import atheris

# CycloneDX spec versions the tool knows about. Mostly valid, with a couple of
# odd values to exercise the version-dependent branches.
_SPEC_VERSIONS = ["1.6", "1.5", "1.4", "1.3", "1.7", "", "9.9", "1"]

# Keep generated structures bounded so a single input stays fast and the fuzzer
# spends its time on logic rather than on multi-megabyte allocations.
_MAX_COMPONENTS = 12
_MAX_DEPTH = 4
_MAX_DEPENDENCIES = 8
_MAX_VULNERABILITIES = 6
_MAX_LIST = 6


def _maybe(fdp: atheris.FuzzedDataProvider) -> bool:
    """Coin flip driven by the fuzzer."""
    return fdp.ConsumeBool()


def _string(fdp: atheris.FuzzedDataProvider, max_len: int = 32) -> str:
    return fdp.ConsumeUnicodeNoSurrogates(max_len)


def _purl(fdp: atheris.FuzzedDataProvider) -> str:
    # Sometimes emit a realistic-looking purl, sometimes a raw fuzzed string so
    # both the "parses fine" and "garbage" paths are covered.
    if _maybe(fdp):
        return f"pkg:{_string(fdp, 12)}/{_string(fdp, 16)}@{_string(fdp, 12)}"
    return _string(fdp, 48)


def _version_range(fdp: atheris.FuzzedDataProvider) -> str:
    # Bias towards the univers "vers" grammar so the range parser is exercised.
    if _maybe(fdp):
        scheme = fdp.PickValueInList(["generic", "npm", "pypi", "maven", "nuget", "deb", "gem"])
        return f"vers:{scheme}/{_string(fdp, 24)}"
    return _string(fdp, 32)


def _component(fdp: atheris.FuzzedDataProvider, depth: int) -> dict:
    component: dict = {"type": "library"}

    if _maybe(fdp):
        component["bom-ref"] = _string(fdp, 24)
    if _maybe(fdp):
        component["name"] = _string(fdp, 24)
    if _maybe(fdp):
        component["version"] = _string(fdp, 16)
    if _maybe(fdp):
        component["group"] = _string(fdp, 16)
    if _maybe(fdp):
        component["purl"] = _purl(fdp)
    if _maybe(fdp):
        component["cpe"] = _string(fdp, 48)
    if _maybe(fdp):
        component["supplier"] = {"name": _string(fdp, 16)}
    if _maybe(fdp):
        component["author"] = _string(fdp, 16)
    if _maybe(fdp):
        component["copyright"] = _string(fdp, 16)
    if _maybe(fdp):
        component["licenses"] = [
            {"license": {"name": _string(fdp, 16)}}
            for _ in range(fdp.ConsumeIntInRange(0, _MAX_LIST))
        ]

    # Bounded recursion to exercise the component-tree walkers without instantly
    # bottoming out in RecursionError (which we already know is catchable).
    if depth < _MAX_DEPTH and _maybe(fdp):
        n = fdp.ConsumeIntInRange(0, 3)
        component["components"] = [_component(fdp, depth + 1) for _ in range(n)]

    return component


def _vulnerability(fdp: atheris.FuzzedDataProvider) -> dict:
    vuln: dict = {}
    if _maybe(fdp):
        vuln["id"] = _string(fdp, 24)
    if _maybe(fdp):
        vuln["references"] = [
            {"id": _string(fdp, 16), "source": {"name": _string(fdp, 12)}}
            for _ in range(fdp.ConsumeIntInRange(0, _MAX_LIST))
        ]
    if _maybe(fdp):
        affects = []
        for _ in range(fdp.ConsumeIntInRange(0, _MAX_LIST)):
            affected: dict = {"ref": _string(fdp, 16)}
            if _maybe(fdp):
                affected["versions"] = [
                    {"range": _version_range(fdp)}
                    if _maybe(fdp)
                    else {"version": _string(fdp, 12)}
                    for _ in range(fdp.ConsumeIntInRange(0, 3))
                ]
            affects.append(affected)
        vuln["affects"] = affects
    if _maybe(fdp):
        vuln["ratings"] = [{"severity": _string(fdp, 8)}]
    return vuln


def build_sbom(fdp: atheris.FuzzedDataProvider) -> dict:
    """Builds a plausible-but-adversarial SBOM dict from fuzzer bytes."""
    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": fdp.PickValueInList(_SPEC_VERSIONS),
    }

    if _maybe(fdp):
        sbom["serialNumber"] = "urn:uuid:" + _string(fdp, 36)
    if _maybe(fdp):
        sbom["version"] = fdp.ConsumeIntInRange(0, 5)

    if _maybe(fdp):
        metadata: dict = {}
        if _maybe(fdp):
            metadata["timestamp"] = _string(fdp, 32)
        if _maybe(fdp):
            metadata["component"] = _component(fdp, 0)
        if _maybe(fdp):
            metadata["authors"] = [{"name": _string(fdp, 16)}]
        sbom["metadata"] = metadata

    if _maybe(fdp):
        n = fdp.ConsumeIntInRange(0, _MAX_COMPONENTS)
        sbom["components"] = [_component(fdp, 0) for _ in range(n)]

    if _maybe(fdp):
        n = fdp.ConsumeIntInRange(0, _MAX_DEPENDENCIES)
        sbom["dependencies"] = [
            {
                "ref": _string(fdp, 16),
                "dependsOn": [
                    _string(fdp, 16) for _ in range(fdp.ConsumeIntInRange(0, _MAX_LIST))
                ],
            }
            for _ in range(n)
        ]

    if _maybe(fdp):
        n = fdp.ConsumeIntInRange(0, _MAX_VULNERABILITIES)
        sbom["vulnerabilities"] = [_vulnerability(fdp) for _ in range(n)]

    if _maybe(fdp):
        sbom["compositions"] = [
            {
                "aggregate": _string(fdp, 12),
                "assemblies": [
                    _string(fdp, 16) for _ in range(fdp.ConsumeIntInRange(0, _MAX_LIST))
                ],
            }
            for _ in range(fdp.ConsumeIntInRange(0, 3))
        ]

    return sbom
