============
validate
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: validate

    Validates an SBOM against a JSON schema.

Schema selection
----------------

This tool can validate SBOMs against any user-provided JSON schema but for convenience, two schema types are built in:

* The *default* schema type validates against the `stock CycloneDX schema <https://github.com/CycloneDX/specification>`_.
* The *strict* schema type refers to the strict variants of the stock CycloneDX schema which were discontinued after version 1.3.
* The *custom* schema type uses a more restrictive schema which accepts a subset of CycloneDX. Additional requirements incorporated into the schema mostly originate from the `NTIA <https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf>`_.

You can select the schema with the ``--schema-type`` or ``--schema-path`` options::

    cdx-ev validate bom.json [--schema-type default]           # stock CycloneDX schema
    cdx-ev validate bom.json --schema-type custom              # built-in custom schema
    cdx-ev validate bom.json --schema-path <json_schema.json>  # your own schema

For all built-in schemas, the tool determines the CycloneDX version from the input SBOM. The following versions are currently supported:

=========== ============================
Type        Supported CycloneDX versions
=========== ============================
``default`` 1.2 to 1.6
``strict``  1.2 to 1.3
``custom``  1.3 to 1.6
=========== ============================

Validation of filename
----------------------

The tool, by default, also validates the filename of the SBOM. Which filenames are accepted depends on several command-line options:

* ``--no-filename-validation`` completely disables validation.
* Use ``--filename-pattern`` to provide a custom regex.

    * The filename must be a full match, regex anchors (^ and $) are not required.
    * Regex patterns often include special characters. Pay attention to escaping rules for your shell to ensure proper results.

* In all other cases, the acceptable filenames depend on the selected schema:

    * When using the stock CycloneDX schema (``--schema-type default`` or no option at all) or when using your own schema (``--schema-path`` option), the validator accepts the two patterns recommended by the `CycloneDX specification <https://cyclonedx.org/specification/overview/#recognized-file-patterns>`_: ``bom.json`` or ``*.cdx.json``.
    * When validating against the built-in custom schema (``--schema-type custom``), filenames must match one of these patterns: ``bom.json`` or ``<name>_<version>_<hash>|<timestamp>|<hash>_<timestamp>.cdx.json``. See below for explanations of the placeholders.

``<name>`` and ``<version>`` correspond to the respective fields in ``metadata.component`` in the SBOM.

``<timestamp>`` corresponds to ``metadata.timestamp`` and ``<hash>`` means any value in ``metadata.component.hashes[].content``.

Either ``<timestamp>`` or ``<hash>`` must be present. If both are specified, ``<hash>`` must come first.

Output
------

By default, the command writes human-readable validation results to *stdout* only. For integration into CI/CD several machine-readable report formats are supported as well. To have a report written to a file, select the format using the ``--report-format`` option and an output path using the ``--report-path`` option.

These formats are currently supported:

* `Jenkins warnings-ng-plugin <https://github.com/jenkinsci/warnings-ng-plugin>`_
* `GitLab Code Quality <https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool>`_

Examples::

    # Write human-readable messages to stdout and a report in warnings-ng format to report.json
    cdx-ev validate bom.json --report-format warnings-ng --report-path report.json

    # Write only a report in GitLab Code Quality format to cq.json
    cdx-ev --quiet validate bom.json --report-format gitlab-code-quality --report-path cq.json
