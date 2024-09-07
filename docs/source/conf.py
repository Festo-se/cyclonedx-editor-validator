# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "CycloneDX Editor Validator Tool"
copyright = "2024, Festo SE & Co. KG"
release = "0.18.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ["sphinxarg.ext", "sphinx_rtd_theme", "sphinx.ext.autosectionlabel"]

templates_path = ["_templates"]
exclude_patterns = []

# Make sure the target is unique
autosectionlabel_prefix_document = True

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_css_files = [
    "css/festo-web-essentials.css",
    "https://www.festo.com/fonts/fonts.css",
]
