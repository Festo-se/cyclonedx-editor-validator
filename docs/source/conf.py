# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

from typing import Any

import sphinx
import sphinx.application
from sphinx.ext import autodoc

from cdxev import pkg

project = "CycloneDX Editor Validator Tool"
copyright = "2024, Festo SE & Co. KG"
release = pkg.VERSION

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinxarg.ext",
    "sphinx_rtd_theme",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.autodoc",
]

templates_path = ["_templates"]

# Make sure the target is unique
autosectionlabel_prefix_document = True

# Prevents double-dashes being converted to en-dashes in argparse output.
smartquotes_action = "qe"

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_css_files = [
    "css/festo-web-essentials.css",
    "https://www.festo.com/fonts/fonts.css",
]


class OperationDocumenter(autodoc.MethodDocumenter):
    """
    Extract docstring only for amend operations.
    see https://stackoverflow.com/a/7832437/5726546
    """

    objtype = "operation"

    content_indent = ""

    @classmethod
    def can_document_member(
        cls, member: Any, membername: str, isattr: bool, parent: Any
    ) -> bool:
        return False

    # do not add a header to the docstring
    def add_directive_header(self, sig: str) -> None:
        pass


# Register OperationDocumenter to be used in docs
def setup(app: sphinx.application.Sphinx) -> None:
    app.add_autodocumenter(OperationDocumenter)
