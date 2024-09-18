=====
amend
=====

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: amend

.. note::
    The order of operations cannot be controlled. If you want to ensure two operations run in a certain order you must run the command twice, each time with a different set of operations.

Examples
--------

.. code:: bash

    # Run all default operations on an SBOM.
    cdx-ev amend bom.json

    # Run only the default-author and add-bom-ref operations.
    cdx-ev amend --operation default-author --operation add-bom-ref bom.json

    # Run the add-license-text operation. License texts are stored in a directory named 'license_texts'.
    # Afterwards, run the delete-ambiguous-licenses operation.
    cdx-ev amend --operation add-license-text --license-dir ./license_texts bom.json --output bom.json
    cdx-ev amend --operation delete-ambiguous-licenses bom.json

Operation details
-----------------

add-bom-ref
^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::AddBomRef

add-license-text
^^^^^^^^^^^^^^^^

The operation *add-license-text* can be used to insert known full license texts for licenses identified by name. You can use this, for instance, in workflows where SBOMs are created or edited by hand - so a clutter-free JSON is preferred - then, in a last step, full texts are inserted using this operation.

License texts are inserted only if:

* The license has a ``name`` field.
* The license has no ``id`` field.
* The license has no or an empty ``text.content`` field.
* A matching file is found.

You must provide one file per license text in a flat directory. The stem of the filename, that is everything up to the extension (i.e., up to but not including the last period), must match the license name specified in the SBOM.

Example
"""""""

Given this license in the input SBOM::

    {
        "license": {
            "name": "My license"
        }
    }

the operation would search the full license text in any file named ``My license``, ``My license.txt``, ``My license.md``, or any other extension.
However, the file ``My license.2.txt`` would be disregarded, because its stem (``My license.2``) doesn't match the license name.

compositions
^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::Compositions


default-author
^^^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::DefaultAuthor

delete-ambiguous-licenses
^^^^^^^^^^^^^^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::DeleteAmbiguousLicenses


infer-supplier
^^^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::InferSupplier

license-name-to-id
^^^^^^^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::LicenseNameToId
