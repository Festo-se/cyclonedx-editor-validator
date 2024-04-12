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
* :py:class:`DeleteAmbigiousLicenses` introduces uncertainty about the completeness of the
  license claims made for each component. It is meant to eliminate essentially useless
  clutter but consumers of the SBOM could take the absence of license claims in the SBOM as
  a sign that the component is not licensed. *So it should be used with caution and does not run
  by default.*
* *:py:class:`InferCopyright` is dangerous*. It should only be used in controlled circumstances
  - e.g., when it is known that no unintended components will be affected - because it could
  add entirely false claims with legal relevance to the SBOM.

Implementation notes
--------------------

If you want to add additional operations to the amend command, do it like this:

#. Add a new class whose name is succinct and distinctive. It will be used in the CLI.
#. Subclass :py:class:`Operation`.
#. Override the method defined in the base class, where necessary.
#. Add a docstring to your class. Keep the first line short and clear. It will be used in the CLI
   to describe your operation.
#. If your operation requires additional options provided by the user, add an `__init__()` method.

   * Add any option to `__init__()`'s parameter list. The parameter name will be used as a CLI
     option.
   * You MUST specify a default value.
   * You MUST add a docstring to `__init__()` which describes the parameter. This description will
     be visible in the command-line help text.

#. If you want to add your operation to the default set, add the :py:func:`default` decorator.
   See above about important considerations before doing so.

"""

import datetime
import importlib.resources
import json
import logging
import uuid

from cdxev.amend.process_license import delete_license_unknown, process_license

logger = logging.getLogger(__name__)


def default(cls: type["Operation"]) -> type["Operation"]:
    """
    Decorator to mark default operations.

    Add this decorator to a suclass of `Operation` to make it run if no operations
    are explicitly selected.
    """
    setattr(cls, "_amendDefault", True)
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
    Adds a 'bom-ref' to components which don't have one yet.

    Since the operation isn't easily able to determine the position of the component
    it processes in the component tree, it generates UUIDs for bom-refs.
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
    Declares all component compositions as 'incomplete'.

    According to https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf
    "known unknowns" should be stated, as we can't guarantee completeness,
    compositions should be marked as 'incomplete' for SBOMs.
    This operation erases existing compositions and then adds all components as 'incomplete'.
    """

    __assemblies: list

    def prepare(self, sbom: dict) -> None:
        """
        Clears any existing compositions and creates an empty composition for "incomplete"
        assemblies.
        """

        if "compositions" in sbom:
            del sbom["compositions"]

        sbom["compositions"] = [{"aggregate": "incomplete", "assemblies": []}]

        self.__assemblies = sbom["compositions"][0]["assemblies"]

    def handle_metadata(self, metadata: dict) -> None:
        try:
            self.__add_to_assemblies(metadata["component"]["bom-ref"])
        except KeyError:
            logger.debug(
                "Cannot add meta-component to compositions because it has no bom-ref."
            )
            pass

    def handle_component(self, component: dict) -> None:
        try:
            self.__add_to_assemblies(component["bom-ref"])
        except KeyError:
            logger.debug(
                "Cannot add component to compositions because it has no bom-ref."
            )
            pass

    def __add_to_assemblies(self, bom_ref: str) -> None:
        logger.debug("Added %s to compositions.", bom_ref)
        self.__assemblies.append(bom_ref)


@default
class DefaultAuthor(Operation):
    """Sets component author to 'automated', if missing."""

    def handle_metadata(self, metadata: dict) -> None:
        authors = metadata.setdefault("authors", [])
        if len(authors) == 0:
            logger.debug("Added default author.")
            authors.append({"name": "automated"})


@default
class InferSupplier(Operation):
    """
    Attempts to infer component supplier from other fields.

    At least one of the 'author', 'supplier' or 'publisher' fields must be set on any component but
    the supplier field is desired.
    If not already present this function will, try to infer a 'supplier.name'
    and 'supplier.url'.
    The supplier name will be inferred from:

    - If a 'publisher' is present, it is used as supplier name.
    - If no 'publisher but an 'author' is present, it is used as supplier name.

    The 'supplier.url' will be inferred from the following sources, in order of precedence:

    - If an 'externalReference' of type 'website' is present, it is used as supplier URL.
    - If an 'externalReference' of type 'issue-tracker' is present, it is used as supplier URL.
    - If an 'externalReference' of type 'vcs' is present, it is used as supplier URL.

    For all of the URLs there is the additional condition that they must utilize the http or https
    scheme.
    """

    def infer_supplier(self, component: dict) -> None:
        if "url" not in component.get("supplier", {}):

            if "externalReferences" in component:
                accepted_references = ("website", "issue-tracker", "vcs")
                accepted_url_schemes = ("http://", "https://")
                for key in accepted_references:
                    ext_ref = next(
                        (
                            x
                            for x in component["externalReferences"]
                            if x.get("type") == key
                        ),
                        None,
                    )
                    if ext_ref is not None and (
                        any(
                            ext_ref["url"].startswith(scheme)
                            for scheme in accepted_url_schemes
                        )
                    ):
                        component["supplier"] = component.get("supplier", {})
                        component["supplier"]["url"] = [ext_ref["url"]]
                        logger.debug(
                            "Set supplier of %s to URL: %s",
                            component.get("bom-ref", "<no bom-ref>"),
                            ext_ref["url"],
                        )
                        break

        if "name" not in component.get("supplier", {}):

            if "publisher" in component:
                component["supplier"] = component.get("supplier", {})
                component["supplier"]["name"] = component["publisher"]
                return

            if "author" in component:
                component["supplier"] = component.get("supplier", {})
                component["supplier"]["name"] = component["author"]
                return

    def handle_component(
        self, component: dict, path_to_license_folder: str = ""
    ) -> None:
        self.infer_supplier(component)

    def handle_metadata(self, metadata: dict) -> None:
        component = metadata.get("component", {})
        self.infer_supplier(component)


@default
class LicenseNameToId(Operation):
    """
    Attempts to infer SPDX ids from license names.

    If there are components in "metadata" or "components" containing
    licenses with the entry "name" instead of "id", this operation attempts
    to replace the name with an SPDX-ID, extracted from a provided list of possible license names
    with associated SPDX-ID.

    If the license contains a name and
    a path to a folder with txt files containing license descriptions with the
    naming convention 'license name'.txt is provided,
    the program searches for a file with matching name
    and, if found, copies its content in the field "text".
    """

    def __init__(self, license_dir: str = "") -> None:
        """
        :param license_dir: Path to a folder with txt-files containing license texts to be
                               copied in the SBOM.
        """
        license_names_file = (
            importlib.resources.files(__spec__.parent) / "license_name_spdx_id_map.json"  # type: ignore[name-defined]  # noqa: E501
        )
        license_names_json = license_names_file.read_text(encoding="utf-8-sig")
        self.license_names = json.loads(license_names_json)
        self.license_dir = license_dir

    def handle_metadata(self, metadata: dict) -> None:
        if "component" not in metadata:
            return
        process_license(
            metadata["component"],
            self.license_names,
            self.license_dir,
        )
        delete_license_unknown(metadata["component"])

    def handle_component(self, component: dict) -> None:
        process_license(component, self.license_names, self.license_dir)
        delete_license_unknown(component)


class InferCopyright(Operation):
    """
    Attempts to infer copyright claims from supplier.

    If neither copyright nor license is present on a component but there is a supplier,
    this operation generates the copyright field from the supplier in the format
    `Copyright (c) <supplier.name> <year>, all rights reserved`.
    """

    def infer_copyright(self, component: dict) -> None:
        if "copyright" in component.keys() or "licenses" in component.keys():
            return

        if "supplier" not in component.keys():
            return

        if "name" not in component.get("supplier", {}).keys():
            return

        year = datetime.date.today().year
        supplier_name = component.get("supplier", {}).get("name", "")
        copyright = f"Copyright (c) {year} {supplier_name}"
        component["copyright"] = copyright

    def handle_component(self, component: dict) -> None:
        self.infer_copyright(component)

    def handle_metadata(self, metadata: dict) -> None:
        component = metadata.get("component", {})
        self.infer_copyright(component)


class DeleteAmbigiousLicenses(Operation):
    """
    Deletes license claims which are solely identified by the `name` property.

    Because of the risk involved in accidentally removing important data,
    this operation is disabled by default.
    """

    def _filter_licenses(self, component: dict) -> None:
        if "licenses" not in component:
            return

        licenses = component["licenses"]
        licenses = filter(
            lambda lic: not (
                "license" in lic and list(lic["license"].keys()) == ["name"]
            ),
            licenses,
        )
        component["licenses"] = list(licenses)

    def handle_metadata(self, metadata: dict) -> None:
        if "component" not in metadata:
            return
        self._filter_licenses(metadata["component"])

    def handle_component(self, component: dict) -> None:
        self._filter_licenses(component)
