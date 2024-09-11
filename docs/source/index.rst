CycloneDX Editor Validator Tool
===============================

This command-line tool performs various actions on `CycloneDX <https://cyclonedx.org/>`_ SBOMs. It allows you to modify, merge and validate your Software Bill of Materials (SBOM).
Originally, it was created to validate CycloneDX SBOMs against not only official schema, which is already supported by `cyclonedx-cli <https://github.com/CycloneDX/cyclonedx-cli>`_, but also custom schemas.
Please note that even though we are speaking of "SBOMs", the tool does not have any limitation regarding the variant of CycloneDX BOMs, e.g., it also works with BOMs having only "hardware" included.

This tool also offers command to amend and set, respectively editing information within a BOM. In addition the tool supports merging two or more BOMs.

.. toctree::
   :caption: Documentation
   :maxdepth: 1

   self
   first_steps
   usage/index
   known_limitations

.. toctree::
   :caption: Further information
   :maxdepth: 1

   maintainers
   CONTRIBUTING
