============
merge
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: merge

    Merges two or more CycloneDX input files into one. Inputs can either be specified directly as positional arguments on the command-line or using the ``--from-folder`` option. Files specified as arguments are merged in the order they are given, files in the folder are merged in alphabetical order (see note below).

    If both positional arguments and the ``--from-folder`` option are used, then the position arguments are merged first, followed by the files in the folder. The command will not merge the same file twice, if it is specified on the command-line and also part of the folder.

    When using the ``--from-folder`` option, the program looks for files matching either of the `recommended CycloneDX naming schemes <https://cyclonedx.org/specification/overview/#recognized-file-patterns>`_: ``bom.json`` or ``*.cdx.json``.

Details
---------------

Input files in the folder provided to the ``--from-folder`` option are sorted by name in a platform-specific way. In other words, they are merged in the same order they appear in your operating system's file browser (e.g., Windows Explorer) when sorted by name.

The process runs iteratively, merging two SBOMs in each iteration. In the first round, the second submitted SBOM is merged into the first. In the second round the third would be merged into the result of the first round and so on.

In mathematical terms: :math:`output = (((input_1 * input_2) * input_3) * input_4 ...)`

The merge is per default not hierarchical for the ``components`` field of a ``component`` (`CycloneDX documentation <https://cyclonedx.org/docs/1.6/json/#components_items_components>`_). This means that components that were contained in the ``components`` of an already present component will just be added as new components under the SBOMs' ``components`` sections.
The ``--hierarchical`` flag allows for hierarchical merges. This affects only the top level components of the merged SBOM. The structured of nested components is preserved in both cases (except the removal of already present components), as shown for "component 4" in the image below.

.. image:: /img/merge_hierarchical_structure.svg
    :alt: Merge components structure default and hierarchical.

A few notes on the merge algorithm:

- The ``metadata`` field is always retained from the first input and never changed through a merge with the exception of the ``timestamp``.
- The command merges the contents of the fields ``components``, ``dependencies``, ``compositions`` and ``vulnerabilities``.
- Components are merged into the result in the order they **first** appear in the inputs. If any subsequent input specifies the same component (sameness in this case being defined as having identical identifying attributes such as ``name``, ``version``, ``purl``, etc.), the later instance of the component will be dropped with a warning. **This command cannot be used to merge information inside components.**
- The resulting dependency graph will reflect all dependencies from all inputs. Dependencies from later inputs are always added to the result, even if the component is dropped as a duplicate as described above.
- Uniqueness of *bom-refs* will be ensured.
- The command is able to merge inputs containing only VEX information in the form of a ``vulnerabilities``. To ensure a sensible result, it should be ensured that bom-refs in the affects field reference components of the same SBOM.
- Vulnerabilities, like components, are merged into the result in the order they **first** appear in the inputs.
- If a merged vulnerability contains additional entries in the ``affects`` field, those will be added to the original vulnerability object (duplicates are possible if version ranges are used).
