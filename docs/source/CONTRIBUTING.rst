============
Contributing
============

Welcome to Festo CycloneDX Editor Validator contributing guide, thank you for investing your time in contributing to our project!
To get an overview of the project, read the :doc:`documentation <index>`.

******
Issues
******

-------------
Create Issues
-------------

Before submitting, please ensure that you are using the latests code by performing a :code:`git pull`. Also, please ensure that an issue does not already exists.

Always include your python version number (:code:`python --version`) and the tool version (:code:`cdx-ev --version`).

-----------
Solve Issue
-----------
Feel free to assign issues to yourself and make changes to our tool. Please consider the points mentioned :ref:`here <contributing:make changes to cyclonedx editor validator>`.

******************************************
Make changes to CycloneDX Editor Validator
******************************************

-------------
Prerequisites
-------------

* For compatibility reasons, the code should be compliant to python 3.10 or higher.
* Make sure to use the latest code by performing a :code:`git pull`.
* For a major change it is recommended that you get in touch with us by :ref:`creating an issue <contributing:create issues>` to discuss changes prior to dedicating time and resources. This process allows us to better coordinate our efforts and prevent duplication of work.
* Commit your changes using a descriptive commit message that follows our :ref:`commit message format <contributing:commit message format>`. The same applies for titles of PRs. This is required as we generate our release notes from these messages.
* Otherwise, feel free to directly [submit a pull request](#submitting-pull-requests).

----------------------------------------
Write new commands, options or arguments
----------------------------------------

Please consider the following rules for commands, options and arguments:

+----------------------------+--------------------------------+-------------------------------------------+
| Argument type              | Style                          | Examples                                  |
+============================+================================+===========================================+
| Subcommand                 | kebab-case [#f1]_              | `cdx-ev init-sbom`                        |
+----------------------------+--------------------------------+-------------------------------------------+
| Option                     | kebab-case                     | `cdx-ev --issues-file`                    |
+----------------------------+--------------------------------+-------------------------------------------+
| Option value               | <kebab-case> [#f1]_            | `cdx-ev --issues-file <file>`             |
+----------------------------+--------------------------------+-------------------------------------------+
| Positional argument        | <snake_case>                   | `cdx-ev merge <sbom_file>`                |
+----------------------------+--------------------------------+-------------------------------------------+
| Optional position argument | [<kebab-case>]                 | No good examples, yet.                    |
+----------------------------+--------------------------------+-------------------------------------------+

.. rubric:: Footnotes:

.. [#f1] Avoid more than one word.

------------------------
Submitting Pull Requests
------------------------

The following things are to consider before submitting a pull request.

1. All `tests <https://github.com/Festo-se/cyclonedx-editor-validator/tree/main/tests>`_ should be passing.

2. If you provide a new feature also include tests for it.

3. Please ensure that types are correct according to `mypy <mypy_url>`_.

4. All submitted code should conform to `PEP8 <pep8_url>`_ and `black <black_url>`_.

5. The code should be python 3.10 compliant.

.. _black_url: https://black.readthedocs.io/en/stable/index.html
.. _pep8_url: https://www.python.org/dev/peps/pep-0008/
.. _mypy_url: https://www.mypy-lang.org/

---------------------
Commit Message Format
---------------------

The message format was mainly inspired by the `guidelines <https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#-git-commit-guidelines>`_ of Angular.

Please use the following format:

.. code-block:: bash

   <type>: <subject>

   <optional footer with additional details>

^^^^
Type
^^^^

Must be one of the following:

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **refactor**: A code change that neither fixes a bug nor adds a feature. (e.g., style or performance changes)
- **tests**: Adding missing or correcting existing tests
- **chore**: Changes to the build process or auxiliary tools and libraries such as documentation generation

^^^^^^^
Subject
^^^^^^^

The subject contains succinct description of the change:

- Use the imperative, present tense: "change" not "changed" nor "changes"
- Don't capitalize first letter
- No dot (.) at the end
- Do not describe the reason of the change, describe the content of the change (what, not why).

^^^^^^^^
Examples
^^^^^^^^

:code:`fix: do not add license option to default operations`

:code:`feat: add 'amend' option`

:code:`refactor: apply black`
