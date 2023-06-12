
[![build and test](https://github.com/Festo-se/cyclonedx-editor-validator/actions/workflows/main.yml/badge.svg)](https://github.com/Festo-se/cyclonedx-editor-validator/actions/workflows/main.yml)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

# CycloneDX Editor/Validator

This command-line tool performs various actions on [CycloneDX](https://cyclonedx.org/) SBOMs. It allows you to modify and validate your SBOMs.

## Documentation

* [Official documentation](https://festo-se.github.io/cyclonedx-editor-validator).
* [Available commands](https://github.com/Festo-se/cyclonedx-editor-validator/blob/main/docs/available_commands.md).
* [Known Limitations](https://github.com/Festo-se/cyclonedx-editor-validator/blob/main/docs/known_limitations.md).

## Contributing

See our [Contributing guidelines](https://github.com/Festo-se/cyclonedx-editor-validator/blob/main/docs/CONTRIBUTING.md).

## To-do

* **Add possibility for adding a configuration-file.** This could be useful for e.g. configuration of validator as the used flags remain the same.
* **Add plausibility check.** This would be used for e.g. finding orphaned `bom-refs`. One further use case would be plausibility check of VEX.
* **Use model from ["official" python lib](https://github.com/CycloneDX/cyclonedx-python-lib/tree/main).** This helps working on classes instead of dicts, which would make our code more robust.
* **Add function for initialization of a SBOM.** Create initial SBOM, so that somebody creating a SBOM manually has a first draft.
* **Add support for SPDX.** This must still be discussed as currently most users rely on CycloneDX.
* **Add possibility to search within SBOM.** This could be used to e.g. retrieve all information for a specific component.
* **Configure mypy to strict mode.** This would simply increase our code quality.
* **Use [json-source-map](https://pypi.org/project/json-source-map/) for better validation errors.** This would be useful for e.g. using within a VS Code extension to receive the incorrect line.
