=====
amend
=====

.. argparse::
    :filename: ../../cdxev/__main__.py
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

    # Build hierarchical bom-refs from nested components.
    cdx-ev amend --operation hierarchical-bom-refs bom.json

    # Add missing bom-refs first, then build the hierarchy in a separate run.
    cdx-ev amend --operation add-bom-ref bom.json --output bom.json
    cdx-ev amend --operation hierarchical-bom-refs bom.json

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


hierarchical-bom-refs
^^^^^^^^^^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::HierarchicalBomRefs

This operation follows structural containment expressed by a component's ``components`` array.
It does not infer hierarchy from ``dependencies`` and does not place ordinary top-level
``components`` beneath ``metadata.component``.

For example, these nested component references::

    {
        "bom-ref": "module-a",
        "components": [
            {
                "bom-ref": "library-b",
                "components": [
                    {"bom-ref": "application-c"}
                ]
            }
        ]
    }

become::

    {
        "bom-ref": "module-a",
        "components": [
            {
                "bom-ref": "module-a/library-b",
                "components": [
                    {"bom-ref": "module-a/library-b/application-c"}
                ]
            }
        ]
    }

The operation has the following behavior:

* Top-level component bom-refs remain unchanged.
* Nesting is processed recursively at any depth, including beneath ``metadata.component``.
* Every bom-ref is treated as an opaque string. Values such as ``1``, arbitrary words, UUIDs, and
    PURLs are preserved in full and are never parsed as path segments.
* Running the operation repeatedly prepends the hierarchy repeatedly. The operation cannot infer
    from an opaque bom-ref whether a prefix was added by an earlier run.
* References in dependencies, compositions, and vulnerability affects are updated to the
    rewritten bom-refs.
* A generated path that conflicts with another bom-ref receives an incrementing suffix such as
  ``-1``.
* A component without a bom-ref, or whose parent has no bom-ref, cannot be adjusted. The operation
    logs this at INFO level, leaves that relationship unchanged, and continues with the remaining
    component tree.
* Run ``add-bom-ref`` in a separate amend invocation before this operation if missing bom-refs
    should be generated. Operation ordering within one amend invocation cannot provide this order.

The operation is not enabled by default because changing bom-refs can affect systems outside the
SBOM that refer to the old values.


infer-supplier
^^^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::InferSupplier

license-name-to-id
^^^^^^^^^^^^^^^^^^

.. autooperation:: cdxev.amend.operations::LicenseNameToId
