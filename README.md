
[![build and test](https://github.com/Festo-se/cyclonedx-editor-validator/actions/workflows/main.yml/badge.svg)](https://github.com/Festo-se/cyclonedx-editor-validator/actions/workflows/main.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Festo-se/cyclonedx-editor-validator/badge)](https://scorecard.dev/viewer/?uri=github.com/Festo-se/cyclonedx-editor-validator)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
[![Static Badge](https://img.shields.io/badge/CycloneDX-v1.2%2C1.3%2C1.4%2C1.5%2C1.6-blue?link=https%3A%2F%2Fcyclonedx.org%2Fdocs%2F1.6%2Fjson%2F%23)](https://cyclonedx.org/docs/1.6/json/)

# CycloneDX Editor/Validator

This command-line tool performs various actions on [CycloneDX](https://cyclonedx.org/) SBOMs. It allows you to modify, merge and validate your Software Bill of Materials (SBOM).

The tool is built with automation in mind, i.e. usage within CI/CD. We try to be as scriptable as possible with various command-line flags, avoiding interactive prompts, providing multiple output options and fine-grained exit codes.

## Command overview

|   Command | Description |
| :-- | :-- |
| [amend](https://festo-se.github.io/cyclonedx-editor-validator/usage/amend.html) | Accepts a single input file and will apply one or multiple *operations* to it. Each operation modifies certain aspects of the SBOM. These modifications cannot be targeted at individual components in the SBOM which sets the *amend* command apart from [*set*](https://festo-se.github.io/cyclonedx-editor-validator/usage/set.html). Its use-case is ensuring an SBOM fulfils certain requirements in an automated fashion. |
| [build-public](https://festo-se.github.io/cyclonedx-editor-validator/usage/build-public.html) | Creates a redacted version of an SBOM fit for publication. |
| [init-sbom](https://festo-se.github.io/cyclonedx-editor-validator/usage/init-sbom.html) | Provides a first draft of an SBOM for manual completion. |
| [list](https://festo-se.github.io/cyclonedx-editor-validator/usage/list.html) | Lists content of the SBOM. |
| [merge](https://festo-se.github.io/cyclonedx-editor-validator/usage/merge.html) | Merges two or more CycloneDX documents into one. |
| [merge-vex](https://festo-se.github.io/cyclonedx-editor-validator/usage/merge-vex.html) | *[Deprecated]* Merges the *vex* information in two or more CycloneDX documents into one. |
| [set](https://festo-se.github.io/cyclonedx-editor-validator/usage/set.html) | Sets properties on specified components to specified values. If a component in an SBOM is missing a particular property or the property is present but has a wrong value, this command can be used to modify just the affected properties without changing the rest of the SBOM. |
| [validate](https://festo-se.github.io/cyclonedx-editor-validator/usage/validate.html) | Validate the SBOM against a built-in or user-provided JSON schema. |

## Installation and usage

This tool is published on [PyPi](https://pypi.org/project/cyclonedx-editor-validator/).

For detailed installation and usage guides, please refer to our [official documentation](https://festo-se.github.io/cyclonedx-editor-validator).

## Contributing

See our [contribution guidelines](https://festo-se.github.io/cyclonedx-editor-validator/CONTRIBUTING/).

## License

This software is made available under the GNU General Public License v3 (GPL-3.0-or-later).
