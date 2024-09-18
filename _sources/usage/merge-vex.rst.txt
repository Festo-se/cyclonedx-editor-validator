============
merge-vex
============

.. admonition:: Deprecated

    The ``merge-vex`` command will be superseded by a new ``vex`` command in a future version. For further information refer to the `discussion <https://github.com/Festo-se/cyclonedx-editor-validator/issues/156#issuecomment-2058312043>`_.

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: merge-vex

    This command requires two input files, a SBOM and a VEX file that shell be merged.
    The VEX file needs to be compatible with the SBOM.

    If the SBOM does not contain a VEX file, the VEX file simply be added to the SBOM.

    If the SBOM already contains a VEX section, the two VEX files are merged uniquely.
    In the case of duplicate entries, the ratings will be merged. Should two ratings
    of the same method contain a different rating, the newer one will be kept.
