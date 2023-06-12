"""
This module defines the amend operations which can be performed on an SBOM.
It also declares a base class to inherit from when implementing new operations.
"""
import importlib.resources
import json
import logging
import uuid

from cdxev.amend.replace_license_name_with_id import replace_license_name_with_id

logger = logging.getLogger(__name__)


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


class AddBomRefOperation(Operation):
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


class CompositionsOperation(Operation):
    """
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


class DefaultAuthorOperation(Operation):
    """
    If the SBOM metadata doesn't declare an author, this operation sets the field to 'automated'.
    """

    def handle_metadata(self, metadata: dict) -> None:
        authors = metadata.setdefault("authors", [])
        if len(authors) == 0:
            logger.debug("Added default author.")
            authors.append({"name": "automated"})


class InferSupplier(Operation):
    """
    As we need a contact in case of a security incident, at least one of the 'author', 'supplier'
    or 'publisher' fields must be set on any component. If that's not the case, this operation
    attempts to infer the 'supplier' from the following sources, in order of precedence:

    - If an 'externalReference' of type 'website' is present, it is used as supplier URL.
    - If an 'externalReference' of type 'issue-tracker' is present, it is used as supplier URL.
    - If an 'externalReference' of type 'vcs' is present, it is used as supplier URL.

    For all of the URLs there is the additional condition that they must utilize the http or https
    scheme.
    """

    def handle_component(self, component: dict) -> None:
        if (
            ("supplier" in component)
            or ("publisher" in component)
            or ("author" in component)
        ):
            return

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
                    component["supplier"] = {"url": [ext_ref["url"]]}
                    logger.debug(
                        "Set supplier of %s to URL: %s",
                        component.get("bom-ref", "<no bom-ref>"),
                        ext_ref["url"],
                    )
                    return


class ReplaceLicenseNameWithId(Operation):
    """
    If there are components in "metadata" or "components" containing
    licenses with the entry "name" instead of "id", this operation attempts
    to replace the name with an id, extracted from a provided list of possible license names
    with associated id.
    """

    list_of_license_names_string = (
        importlib.resources.files("cdxev.amend")
        .joinpath("license_name_id_map.json")
        .read_text(encoding="utf-8-sig")
    )
    list_of_license_names = json.loads(list_of_license_names_string)

    def handle_metadata(self, metadata: dict) -> None:
        if "component" not in metadata:
            return
        replace_license_name_with_id(metadata["component"], self.list_of_license_names)

    def handle_component(self, component: dict) -> None:
        replace_license_name_with_id(component, self.list_of_license_names)
