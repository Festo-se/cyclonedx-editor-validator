# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module defines the amend operations which can be performed on an SBOM.

A few general rules for operations:

One operation, one task. **Do not** make a single operation do lots of different things.
This let's users of the tool decide for themselves which changes to make to their SBOM
by selecting the operations to run.

Be mindful of an operation's impact when deciding to add the :py:func:`default` decorator.
Some operations are always safe to run. Others might introduce uncertainty to the SBOM. These are
a judgment call. Others again might add potentially false claims if used without thought.
**Do not** make these run by default.

Examples:
^^^^^^^^^

* *:py:class:`AddBomRef` is safe.* It never does anything to an SBOM that could change its
  meaning.
* :py:class:`Compositions` introduces an intentional uncertainty about the completeness of the
  SBOM's information. *We deem it okay to run by default because at worst it means the SBOM is
  a little less expressive than it could be.*
* :py:class:`DeleteAmbiguousLicenses` introduces uncertainty about the completeness of the
  license claims made for each component. It is meant to eliminate essentially useless
  clutter but consumers of the SBOM could take the absence of license claims in the SBOM as
  a sign that the component is not licensed. *So it should be used with caution and does not run
  by default.*

Implementation notes
--------------------

If you want to add additional operations to the amend command, do it like this:

#. Add a new class whose name is succinct and distinctive. It will be used in the CLI.
#. Subclass :py:class:`Operation`.
#. Override the methods defined in the base class, where necessary.
#. Add a docstring to your class.

   * It will be exposed on the CLI so **do not** add any formatting syntax. Stick to raw text.
   * Keep the first line short and clear. It will be part of the general help for the *amend*
     command.

#. If your operation requires additional options provided by the user, add an `__init__()` method.

   * Add any option to `__init__()`'s parameter list. The parameter name will be used as a CLI
     option.
   * You MUST specify a default value.
   * You MUST add a docstring to `__init__()` which describes the parameter. This description will
     be visible in the command-line help text.

#. If you want to add your operation to the default set, add the :py:func:`default` decorator.
   See above about important considerations before doing so.

"""

import importlib.resources
import json
import logging
import typing as t
import uuid
from pathlib import Path

import charset_normalizer

from cdxev.amend.license import foreach_license, license_has_id, license_has_text
from cdxev.auxiliary.identity import ComponentIdentity
from cdxev.error import AppError
from cdxev.log import LogMessage

logger = logging.getLogger(__name__)


def default(cls: type["Operation"]) -> type["Operation"]:
    """
    Decorator to mark default operations.

    Add this decorator to a subclass of `Operation` to make it run if no operations
    are explicitly selected.
    """
    setattr(cls, "_amendDefault", True)  # noqa: B010
    return cls


class Operation:
    """
    Base class for operations which modify the SBOM.
    Subclasses should override these methods where necessary.
    """

    def prepare(self, sbom: dict) -> None:
        """
        The prepare method will be called once before starting the walk through the SBOM.
        It gets passed the entire SBOM object.
        """

    def handle_metadata(self, metadata: dict) -> None:
        """
        This method is invoked once for the metadata object, if it exists.
        """

    def handle_component(self, component: dict) -> None:
        """
        This method is invoked for every component in the 'components' tree.
        The tree-traversal goes depth-first.
        """


@default
class AddBomRef(Operation):
    """
    Adds a ``bom-ref`` to components which don't have one yet.

    This operation generates bom-refs comprising a single UUIDv4 for any component which doesn't
    have an SBOM.
    """

    def handle_metadata(self, metadata: dict) -> None:
        if "component" in metadata:
            self._add_bom_ref(metadata["component"])

    def handle_component(self, component: dict) -> None:
        self._add_bom_ref(component)

    def _add_bom_ref(self, component: dict) -> None:
        if "bom-ref" not in component:
            component["bom-ref"] = str(uuid.uuid4())


@default
class Compositions(Operation):
    """
    Declares all component compositions as ``unknown``.

    Any existing entries in ``compositions`` are replaced by a single entry that marks all
    components in the SBOM as ``unknown``. This serves two goals:

    * The NTIA recommends that known unknowns be made explicit. See
      https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf
    * It is safer to err on the side of caution when making claims about completeness.

    This excludes the metadata component because any SBOM supplier should be able to state the
    level of completeness of its first-level components.
    """

    __compositions: list
    __unknown_assemblies: list
    __metacomp_aggregate: t.Optional[str]

    def prepare(self, sbom: dict) -> None:
        """
        Clears any existing compositions and creates an empty composition for "unknown"
        assemblies.
        """

        metacomp = sbom.get("metadata", {}).get("component", {}).get("bom-ref", None)
        self.__compositions = sbom.setdefault("compositions", [])

        # Remember the old aggregate of the metadata component
        self.__metacomp_aggregate = next(
            (
                comp["aggregate"]
                for comp in self.__compositions
                if metacomp in comp.get("assemblies", [])
            ),
            None,
        )

        # Replace any existing compositions with a new, empty list
        self.__compositions.clear()
        self.__compositions.append({"aggregate": "unknown", "assemblies": []})
        self.__unknown_assemblies = self.__compositions[0]["assemblies"]

    def handle_metadata(self, metadata: dict) -> None:
        metacomp = metadata.get("component", {}).get("bom-ref", None)
        if not metacomp or not self.__metacomp_aggregate:
            return

        try:
            composition = next(
                comp
                for comp in self.__compositions
                if comp["aggregate"] == self.__metacomp_aggregate
            )
            assemblies = composition.setdefault("assemblies", [])
            self.__append_unique_assembly(assemblies, metacomp)
        except StopIteration:
            composition = {
                "aggregate": self.__metacomp_aggregate,
                "assemblies": [metacomp],
            }
            self.__compositions.append(composition)

    def handle_component(self, component: dict) -> None:
        try:
            self.__add_to_assemblies(component["bom-ref"])
        except KeyError:
            logger.debug("Cannot add component to compositions because it has no bom-ref.")

    def __add_to_assemblies(self, bom_ref: str) -> None:
        logger.debug("Added %s to compositions.", bom_ref)
        self.__append_unique_assembly(self.__unknown_assemblies, bom_ref)

    @staticmethod
    def __append_unique_assembly(assemblies: list, bom_ref: str) -> None:
        if bom_ref not in assemblies:
            assemblies.append(bom_ref)


@default
class DefaultAuthor(Operation):
    """Sets author of the SBOM in metadata to ``automated``, if missing."""

    def handle_metadata(self, metadata: dict) -> None:
        authors = metadata.setdefault("authors", [])
        if len(authors) == 0:
            logger.debug("Added default author.")
            authors.append({"name": "automated"})


@default
class InferSupplier(Operation):
    """
    Attempts to infer component supplier from other fields.

    CycloneDX contains numerous attributes on components to attest some sort of responsibility for
    its creation or distribution with fine semantic differences between them. These include
    ``author``, ``authors``, ``manufacturer``, ``supplier``, or ``publisher`` and the list might
    grow in future versions.
    Unfortunately, the toolscape doesn't work equally well with all of these. For instance,
    Dependency-Track ignores everything but ``author`` and ``supplier``.
    However, SBOMs generated by many tools do not always expose this information for all
    components. Where it is missing, this operation attempts to infer a ``supplier`` from available
    data.

    The algorithm sets the ``supplier.name`` to the first element found from the following list:

    * ``publisher``
    * ``author``

    The ``supplier.url`` will be inferred from the following sources, in order of precedence:

    * ``externalReference`` of type ``website``
    * ``externalReference`` of type ``issue-tracker``
    * ``externalReference`` of type ``vcs``

    For all of the URLs there is the additional condition that they must utilize either the
    ``http`` or ``https`` scheme.
    """

    def infer_supplier(self, component: dict) -> None:
        if "supplier" in component:
            return

        supplier = {}

        if "externalReferences" in component:
            accepted_references = ("website", "issue-tracker", "vcs")
            accepted_url_schemes = ("http://", "https://")
            for key in accepted_references:
                ext_ref = next(
                    (x for x in component["externalReferences"] if x.get("type") == key),
                    None,
                )
                if ext_ref is not None and (
                    any(ext_ref["url"].startswith(scheme) for scheme in accepted_url_schemes)
                ):
                    supplier["url"] = [ext_ref["url"]]
                    logger.debug(
                        "Set supplier of %s to URL: %s",
                        component.get("bom-ref", "<no bom-ref>"),
                        ext_ref["url"],
                    )
                    break

        if "publisher" in component:
            supplier["name"] = component["publisher"]
        elif "author" in component:
            supplier["name"] = component["author"]

        if supplier:
            component["supplier"] = supplier

    def handle_component(self, component: dict) -> None:
        self.infer_supplier(component)

    def handle_metadata(self, metadata: dict) -> None:
        component = metadata.get("component", {})
        self.infer_supplier(component)


@default
class LicenseNameToId(Operation):
    """
    Attempts to infer SPDX ids from license names.

    For any license on a component or the metadata component that is declared with a name but no
    id, this operation attempts to replace the name with a matching SPDX id. The operation
    contains a lookup table of common license names to SPDX ids largely sourced from
    https://github.com/CycloneDX/cyclonedx-core-java/ and https://spdx.org/licenses/.

    Licenses that already have an id are skipped. If no corresponding id can be found, the license
    is also skipped.
    """

    license_map: dict[str, str] = {}

    def prepare(self, sbom: dict) -> None:
        license_mapping_file = (
            importlib.resources.files(__spec__.parent) / "license_name_spdx_id_map.json"  # type: ignore[arg-type]  # noqa: E501
        )
        license_mapping_json = license_mapping_file.read_text(encoding="utf_8_sig")
        license_mapping = json.loads(license_mapping_json)
        for mapping in license_mapping:
            for name in mapping["names"]:
                self.license_map[name.lower()] = mapping["exp"]

    def _do_it(self, license: dict, component: dict) -> None:
        if license_has_id(license):
            return

        name = license["name"].lower()
        if name not in self.license_map:
            return

        id = self.license_map[name]
        license["id"] = id
        del license["name"]

        component_id = ComponentIdentity.create(component, True)
        logger.info(
            LogMessage(
                "License name replaced with id",
                f"License '{name}' of component {component_id} replaced with id '{id}'",
            )
        )

    def handle_metadata(self, metadata: dict) -> None:
        if "component" not in metadata:
            return

        foreach_license(self._do_it, metadata["component"])

    def handle_component(self, component: dict) -> None:
        foreach_license(self._do_it, component)


class AddLicenseText(Operation):
    """
    Adds user-provided license texts to licenses with a specific name (not id).

    When using this operation, the user must also specify a directory where license texts are
    stored.
    Texts are expected in one file per license, where the filename must match the license name
    declared in the SBOM. The filename's extension is ignored or might even be missing.

    This operation skips licenses with an SPDX id as well as licenses which already contain a text.
    """

    license_files: dict[str, Path] = {}
    """Maps filenames to path."""
    aliases: dict[str, str] = {}
    """Maps filename without extension to full filename."""

    def __init__(self, license_dir: Path) -> None:
        """
        :param license_dir: Path to a folder with files containing license texts.
        """
        self.license_dir = license_dir

    def _add_text(self, license: dict, text: str) -> None:
        license["text"] = {"content": text}

    def _find_text(self, license_name: str) -> t.Optional[str]:
        if license_name in self.aliases:
            license_name = self.aliases[license_name]

        if license_name not in self.license_files:
            return None

        file = self.license_files[license_name]
        match = charset_normalizer.from_path(file).best()
        if match is None:
            raise AppError("File encoding cannot be determined", module_name=str(file))
        text = str(match)
        # Escape string for inclusion in json. The slice is to remove the surrounding
        # double-quotes added by json.dumps()
        return json.dumps(text)[1:-1]

    def _do_it(self, license: dict, component: dict) -> None:
        if license_has_id(license) or license_has_text(license):
            return

        name = license["name"]
        text = self._find_text(name.lower())
        if text:
            component_id = ComponentIdentity.create(component, True)
            logger.info(
                LogMessage(
                    "License text added",
                    f"Added text of license '{name}' to component {component_id}",
                )
            )
            self._add_text(license, text)

    def prepare(self, sbom: dict) -> None:
        if not self.license_dir.is_dir():
            raise AppError(
                "License directory not found",
                "Not found or not a directory: " + str(self.license_dir),
            )

        listing = (file for file in self.license_dir.glob("*") if file.is_file())
        for file in listing:
            self.license_files[file.name.lower()] = file
            self.aliases[file.stem.lower()] = file.name.lower()

    def handle_metadata(self, metadata: dict) -> None:
        if "component" not in metadata:
            return

        foreach_license(self._do_it, metadata["component"])

    def handle_component(self, component: dict) -> None:
        foreach_license(self._do_it, component)


class DeleteAmbiguousLicenses(Operation):
    """
    Deletes license claims which are solely identified by the ``name`` property.

    Licenses that contain only a name property but no URL or text for context provide little
    informational value beyond the fact that some form of license is present.
    In certain cases it can therefore be beneficial to remove such clutter from an SBOM.

    Because of the risk involved in accidentally removing important data, this operation is
    disabled by default.
    """

    def _has_text(self, license: dict) -> bool:
        if license.get("text", {}).get("content", "") != "":
            return True
        else:
            return False

    def _has_url(self, license: dict) -> bool:
        if license.get("url", "") != "":
            return True
        else:
            return False

    def _has_name_only(self, license: dict) -> bool:
        # Any fields other than name, text, or url mean the license shouldn't be deleted.
        if any(field not in ["name", "text", "url"] for field in license.keys()):
            return False

        # Make sure that, if name or url are present, they aren't empty.
        return not (self._has_text(license) or self._has_url(license))

    def _keep_license(self, license: dict) -> bool:
        if "license" not in license:
            return True

        return not self._has_name_only(license["license"])

    def _filter_licenses(self, component: dict) -> None:
        if "licenses" not in component:
            return

        licenses = component["licenses"]
        licenses = list(
            filter(
                self._keep_license,
                licenses,
            )
        )
        if licenses:
            component["licenses"] = licenses
        else:
            del component["licenses"]

    def handle_metadata(self, metadata: dict) -> None:
        if "component" not in metadata:
            return
        self._filter_licenses(metadata["component"])

    def handle_component(self, component: dict) -> None:
        self._filter_licenses(component)


class CleanupSelfReferences(Operation):
    """
    Removes accidental duplicate of metadata component from components.

    Legacy merge behavior could create SBOMs where ``metadata.component`` is also present in
    ``components`` with a different ``bom-ref``. This operation removes those duplicates,
    preserves additional data by merging it into ``metadata.component`` and rewrites affected
    references in dependencies, compositions and vulnerability affects.
    """

    def prepare(self, sbom: dict) -> None:
        metadata_component = sbom.get("metadata", {}).get("component")
        if not isinstance(metadata_component, dict) or not metadata_component:
            return

        metadata_ref = self._ensure_bom_ref(metadata_component)
        duplicate_refs = self._remove_duplicates_and_merge_data(sbom, metadata_component)
        if not duplicate_refs:
            return

        for duplicate_ref in duplicate_refs:
            self._replace_ref_in_dependencies(sbom, duplicate_ref, metadata_ref)
            self._replace_ref_in_compositions(sbom, duplicate_ref, metadata_ref)
            self._replace_ref_in_vulnerabilities(sbom, duplicate_ref, metadata_ref)

        self._merge_dependencies_for_ref(sbom, metadata_ref)

    def _ensure_bom_ref(self, metadata_component: dict) -> str:
        metadata_ref = metadata_component.get("bom-ref")
        if isinstance(metadata_ref, str) and metadata_ref:
            return metadata_ref

        identity = ComponentIdentity.create(metadata_component, allow_unsafe=True)
        metadata_ref = str(identity) if len(identity) > 0 else str(uuid.uuid4())
        metadata_component["bom-ref"] = metadata_ref
        return metadata_ref

    def _remove_duplicates_and_merge_data(self, sbom: dict, metadata_component: dict) -> list[str]:
        duplicate_refs: list[str] = []
        components = sbom.get("components")
        if not isinstance(components, list):
            return duplicate_refs

        self._filter_component_tree(components, metadata_component, duplicate_refs)
        return duplicate_refs

    def _filter_component_tree(
        self,
        components: list[dict],
        metadata_component: dict,
        duplicate_refs: list[str],
    ) -> None:
        index = 0
        while index < len(components):
            component = components[index]
            if self._is_duplicate_of_metadata(component, metadata_component):
                component_ref = component.get("bom-ref")
                if isinstance(component_ref, str) and component_ref:
                    duplicate_refs.append(component_ref)

                self._merge_component_data(metadata_component, component)
                components.pop(index)
                continue

            nested = component.get("components")
            if isinstance(nested, list):
                self._filter_component_tree(nested, metadata_component, duplicate_refs)
            index += 1

    def _normalize_value(self, value: t.Any) -> t.Any:
        if isinstance(value, str):
            return value.strip().lower()

        if isinstance(value, dict):
            return json.dumps(value, sort_keys=True)

        return value

    def _is_duplicate_of_metadata(self, component: dict, metadata_component: dict) -> bool:
        identity_component = ComponentIdentity.create(component, allow_unsafe=True)
        identity_metadata = ComponentIdentity.create(metadata_component, allow_unsafe=True)
        if len(identity_component) == 0 or len(identity_metadata) == 0:
            return False

        for key in ("purl", "cpe", "swid"):
            left = component.get(key)
            right = metadata_component.get(key)
            if left is not None and right is not None:
                if self._normalize_value(left) != self._normalize_value(right):
                    return False

        return identity_component == identity_metadata

    def _merge_component_data(self, target: dict, source: dict) -> None:
        for key, source_value in source.items():
            if key == "bom-ref":
                continue

            if key not in target:
                target[key] = source_value
                continue

            target_value = target[key]
            if isinstance(target_value, dict) and isinstance(source_value, dict):
                self._merge_component_data(target_value, source_value)
            elif isinstance(target_value, list) and isinstance(source_value, list):
                self._merge_lists(target_value, source_value)
            elif self._is_empty(target_value) and not self._is_empty(source_value):
                target[key] = source_value

    def _is_empty(self, value: t.Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return value == ""
        if isinstance(value, (list, dict)):
            return len(value) == 0
        return False

    def _merge_lists(self, target: list, source: list) -> None:
        seen = {self._item_key(item) for item in target}
        for item in source:
            key = self._item_key(item)
            if key not in seen:
                target.append(item)
                seen.add(key)

    def _item_key(self, item: t.Any) -> str:
        if isinstance(item, dict):
            return json.dumps(item, sort_keys=True)
        return str(item)

    def _replace_ref_in_dependencies(self, sbom: dict, old_ref: str, new_ref: str) -> None:
        if old_ref == new_ref:
            return

        dependencies = sbom.get("dependencies")
        if not isinstance(dependencies, list):
            return

        for dependency in dependencies:
            dependency_ref_was_old = dependency.get("ref") == old_ref
            did_change = False
            if dependency.get("ref") == old_ref:
                dependency["ref"] = new_ref
                did_change = True

            depends_on = dependency.get("dependsOn")
            old_ref_in_depends_on = isinstance(depends_on, list) and old_ref in depends_on
            if isinstance(depends_on, list):
                replaced = [new_ref if ref == old_ref else ref for ref in depends_on]
                if replaced != depends_on:
                    dependency["dependsOn"] = replaced
                    did_change = True

            if did_change and isinstance(dependency.get("dependsOn"), list):
                dep_ref = dependency.get("ref")
                cleaned = []
                seen_new_ref = False
                for ref in dependency["dependsOn"]:
                    if (
                        dep_ref == new_ref
                        and ref == new_ref
                        and (dependency_ref_was_old or old_ref_in_depends_on)
                    ):
                        continue
                    if ref == new_ref:
                        if seen_new_ref:
                            continue
                        seen_new_ref = True

                    if ref not in cleaned or ref != new_ref:
                        cleaned.append(ref)
                dependency["dependsOn"] = cleaned

    def _replace_ref_in_compositions(self, sbom: dict, old_ref: str, new_ref: str) -> None:
        if old_ref == new_ref:
            return

        compositions = sbom.get("compositions")
        if not isinstance(compositions, list):
            return

        for composition in compositions:
            assemblies = composition.get("assemblies")
            if not isinstance(assemblies, list) or old_ref not in assemblies:
                continue

            replaced = [new_ref if ref == old_ref else ref for ref in assemblies]
            composition["assemblies"] = self._collapse_ref_occurrences(replaced, new_ref)

    def _replace_ref_in_vulnerabilities(self, sbom: dict, old_ref: str, new_ref: str) -> None:
        if old_ref == new_ref:
            return

        vulnerabilities = sbom.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            return

        for vulnerability in vulnerabilities:
            affects = vulnerability.get("affects")
            if not isinstance(affects, list):
                continue

            if not any(
                isinstance(affected, dict) and affected.get("ref") == old_ref
                for affected in affects
            ):
                continue

            for affected in affects:
                if isinstance(affected, dict) and affected.get("ref") == old_ref:
                    affected["ref"] = new_ref

            self._merge_affects_for_ref(affects, new_ref)

    def _collapse_ref_occurrences(self, refs: list[t.Any], target_ref: str) -> list[t.Any]:
        collapsed = []
        seen_target = False
        for ref in refs:
            if ref == target_ref:
                if seen_target:
                    continue
                seen_target = True
            collapsed.append(ref)
        return collapsed

    def _merge_affects_for_ref(self, affects: list[t.Any], target_ref: str) -> None:
        matching_indices = [
            idx
            for idx, affected in enumerate(affects)
            if isinstance(affected, dict) and affected.get("ref") == target_ref
        ]
        if len(matching_indices) <= 1:
            return

        primary = affects[matching_indices[0]]
        if not isinstance(primary, dict):
            return

        for idx in reversed(matching_indices[1:]):
            candidate = affects[idx]
            if isinstance(candidate, dict):
                primary_versions = primary.get("versions")
                candidate_versions = candidate.get("versions")
                if isinstance(primary_versions, list) and isinstance(candidate_versions, list):
                    self._merge_lists(primary_versions, candidate_versions)
                elif candidate_versions and not primary_versions:
                    primary["versions"] = candidate_versions
            affects.pop(idx)

    def _merge_dependencies_for_ref(self, sbom: dict, ref: str) -> None:
        dependencies = sbom.get("dependencies")
        if not isinstance(dependencies, list):
            return

        matching = [d for d in dependencies if d.get("ref") == ref]
        if len(matching) <= 1:
            return

        # Preserve malformed entries verbatim. Only merge when all matching dependency
        # records have list-based dependsOn values.
        if any(not isinstance(d.get("dependsOn"), list) for d in matching):
            return

        merged_depends_on: list[t.Any] = []
        for dependency in matching:
            depends_on = dependency.get("dependsOn")
            if not isinstance(depends_on, list):
                continue
            for entry in depends_on:
                if entry == ref:
                    continue
                if entry not in merged_depends_on:
                    merged_depends_on.append(entry)

        first_index = next(index for index, d in enumerate(dependencies) if d.get("ref") == ref)
        merged_dependency = dependencies[first_index]
        merged_dependency["dependsOn"] = merged_depends_on

        filtered: list[dict] = []
        seen_target = False
        for dependency in dependencies:
            if dependency.get("ref") != ref:
                filtered.append(dependency)
                continue

            if not seen_target:
                filtered.append(merged_dependency)
                seen_target = True

        sbom["dependencies"] = filtered

