# Welcome to Festo CycloneDX Editor Validator contributing guide

Thank you for investing your time in contributing to our project! To get an overview of the project, read the [documentation](./index.md).

## Issues

### Create Issues

Before submitting, please ensure that you are using the latests code by performing a `git pull`. Also, please ensure that an issue does not already exists.

Always include your python version number (`python --version`) and the tool version (`cdx-ev --version`).

### Solve Issue

Feel free to assign issues to yourself and make changes to our tool. Please consider the points mentioned [here](#make-changes-to-cyclonedx-editor-validator).

## Make changes to CycloneDX Editor Validator

### Prerequisites

- For compatibility reasons, the code should be compliant to python 3.9 or higher.
- Make sure to use the latest code by performing a `git pull`.
- For a major change it is recommended that you get in touch with us by [creating an issue](#create-issues) to discuss changes prior to dedicating time and resources. This process allows us to better coordinate our efforts and prevent duplication of work.
- Commit your changes using a descriptive commit message that follows our [commit message format](#commit-message-format). The same applies for titles of PRs. This is required as we generate our release notes from these messages.
- Otherwise, feel free to directly [submit a pull request](#submitting-pull-requests).

### Write new commands, options or arguments

Please consider the following rules for commands, options and arguments:

| Argument type              | Style                          | Examples                                  |
|----------------------------|--------------------------------|-------------------------------------------|
| Subcommand                 | kebab-case<sup>1</sup>         | `cdx-ev merge-vex`                        |
| Option                     | kebab-case                     | `cdx-ev --issues-file`                    |
| Option value               | &lt;kebab-case&gt;<sup>1</sup> | `cdx-ev --issues-file <file>`             |
| Positional argument        | &lt;snake-case&gt;             | `cdx-ev merge-vex <sbom_file> <vex_file>` |
| Optional position argument | [&lt;kebab-case&gt;]           | No good examples, yet.                    |

Footnotes:

1. Avoid more than one word.

### Submitting Pull Requests

The following things are to consider before submitting a pull request.

1. All [tests](https://github.com/Festo-se/cyclonedx-editor-validator/tree/main/tests) should be passing.

2. If you provide a new feature also include tests for it.

3. Please ensure that types are correct according to [__mypy__][mypy].

4. All submitted code should conform to [__PEP8__][pep8] and [__Black__][black].

5. The code should be python 3.9 compliant.

[black]: https://black.readthedocs.io/en/stable/index.html
[pep8]: https://www.python.org/dev/peps/pep-0008/
[mypy]: https://www.mypy-lang.org/

### Commit Message Format

The message format was mainly inspired by the [guidelines](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#-git-commit-guidelines) of Angular.

Please use the following format:

```format
<type>: <subject>

<optional footer with additional details>
```

#### Type

Must be one of the following:

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **refactor**: A code change that neither fixes a bug nor adds a feature. (e.g., style or performance changes)
- **tests**: Adding missing or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools and libraries such as documentation generation

#### Subject

The subject contains succinct description of the change:

- Use the imperative, present tense: "change" not "changed" nor "changes"
- Don't capitalize first letter
- No dot (.) at the end
- Do not describe the reason of the change, describe the content of the change (what, not why).

#### Examples
`fix: do not add license option to default operations`

`feat: add 'amend' option`

`refactor: apply black`
