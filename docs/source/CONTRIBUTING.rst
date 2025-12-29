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

Before submitting, please ensure that you are using the latests code by performing a :code:`git pull`, respectively :code:`pip install -upgrade cyclonedx-editor-validator`. Also, please ensure that an issue does not already exists.

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
* Otherwise, feel free to directly :ref:`submit a pull request <contributing:submitting pull requests>`.

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

4. All submitted code should conform to `PEP8 <pep8_url>`_ and `ruff <ruff_url>`_.

5. The code should be python 3.10 compliant.

.. _ruff_url: https://docs.astral.sh/ruff/
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

:code:`refactor: apply ruff`

**************************************
Setting up the Development Environment
**************************************

Before you begin, ensure the following are installed:

- Git (for version control)
- Optional: Python 3.10+ (if you plan using `pip` to install `uv`, otherwise `uv` will handle Python installations for you)

---------------
Installing `uv`
---------------

If `uv` is not yet installed on your system:

.. code:: bash

    # macOS / Linux
    curl -LsSf https://astral.sh/uv/install.sh | less

    # Windows (PowerShell)
    powershell -c "irm https://astral.sh/uv/install.ps1 | more"

    # Alternatively, via pip (not recommended)
    pip install uv

This provides `uv`, which automatically handles Python versions, environment creation, dependency resolution, and isolated environments.

**From now on: Do not run Python / pip directly. All Python commands must be run via `uv`.**

-----------------------------------------
Environment Variables for Corporate Usage
-----------------------------------------

Development in corporate contexts may require special environment variables, such as:

- `PRE_COMMIT_HOME`: Specifies the directory for caching `pre-commit` related files.
- `UV_PYTHON_INSTALL_DIR`: Specifies the directory for storing managed Python installations.
- `UV_PYTHON_BIN_DIR`: Specifies the directory to place links to installed, managed Python executables.
- `UV_PYTHON_CACHE_DIR`: Specifies the directory for caching the archives of managed Python installations before installation.
- `UV_CACHE_DIR`: Specifies the directory for caching instead of the default cache directory.

Example export (assuming git bash):

.. code:: bash

    export PRE_COMMIT_HOME=C:/opt/corp/pre-commit
    export UV_PYTHON_INSTALL_DIR=C:/corp/uv
    export UV_PYTHON_BIN_DIR=C:/corp/uv/bin
    export UV_PYTHON_CACHE_DIR=C:/corp/uv/cache
    export UV_CACHE_DIR=C:/corp/uv/cache

You can also maintain a `.bashrc` file that is sourced by your shell as needed.

--------------------------
Setting Up the Environment
--------------------------

For the creation of the development environment, run the following command:

.. code:: bash

    # Using uv to install the correct Python version
    uv python install 3.10

Once inside your project directory:

.. code:: bash

    # Sync and install all declared dependencies (runtime + dev)
    uv sync

This creates and populates the local environment based on `pyproject.toml` and `uv.lock`.

If you want to add dependencies, e.g. for development, use:

.. code:: bash

    uv add --group dev <package-name>


We enforce `pre-commit` to run checks (linters, formatters, etc.) prior to each commit. It should be installed **inside the `uv` environment** and registered for the repository.

1. Install `pre-commit` with `uv`:

   .. code:: bash

       uv tool install pre-commit

2. Register hooks:

   .. code:: bash

       uv run pre-commit install

3. You can also run all pre-commit checks manually:

   .. code:: bash

       uv run pre-commit run --all-files

---------------------------------
Typical Workflow and Contribution
---------------------------------

1. Clone the repository:

   .. code:: bash

       git clone https://github.com/Festo-se/cyclonedx-editor-validator.git

2. Develop features / fix bugs.
3. Add tests if necessary.
4. Validate changes locally (tests, linting, formatting).

.. code:: bash

    uv run coverage run -m pytest
    uv run ruff check cdxev tests --fix
    uv run mypy --install-types --non-interactive --config-file=pyproject.toml
    uv run pre-commit run --all-files

5. Commit changes (pre-commit auto-runs).
6. Push and open a pull request.
