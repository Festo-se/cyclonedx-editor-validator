==================
Available commands
==================

This documentation is automatically created by the `sphinx-argparse <https://sphinx-argparse.readthedocs.io/en/latest/index.html>`_ extension.

Before use, please consider the :doc:`known limitations <known_limitations>` of the tool.

*****
amend
*****

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: amend

************
build-public
************

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: build-public

*****
merge
*****

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: merge

*********
merge-vex
*********

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: merge-vex

    [Deprecated] - The ``merge-vex`` command will be superseded by a new ``vex`` command in a future version. For further information refer to the `discussion <https://github.com/Festo-se/cyclonedx-editor-validator/issues/156#issuecomment-2058312043>`_.

***
set
***

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: set

********
validate
********

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: validate
