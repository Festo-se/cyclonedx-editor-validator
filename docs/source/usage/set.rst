============
set
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: set
    :nodescription:

    This command sets properties on specified components to specified values. If a component in an SBOM is missing a particular property or the property is present but has a wrong value, this command can be used to modify just the affected properties without changing the rest of the SBOM.

    For this command to work, three bits of information must be provided by the user: The *target* component(s) to modify as well as the *name* and *new value* of each property to set on the target component.

    This data can either be passed directly on the command-line — in this case only a single update can be performed per invocation — or in a JSON file — this allows performing an unlimited number of updates in a single invocation.

Target components
-----------------

The *target component* can be identified through any of the identifiable properties defined by CycloneDX, specifically: *cpe*, *purl*, *swid* or the combination of *name*, *group* and/or *version* (collectively called *coordinates*).

If *coordinates* are used to identify the target, they must match the component fully. In other words, if **only** *name* is given, it will **only match** components with that name which do **not** contain *version* or *group* fields.

In *coordinates* it is also possible to provide a range of versions using the *version-range* parameter instead of *version* following the `PURL specification <https://github.com/package-url/purl-spec/blob/master/VERSION-RANGE-SPEC.rst>`_ as referenced by `CycloneDX <https://cyclonedx.org/docs/1.6/json/#vulnerabilities_items_affects_items_versions_items_range>`_.

The version range has the format::

    vers:<versioning-scheme>/<version-constraint>|<version-constraint>|...

beginning with the ``vers`` identifier. Following this the versioning scheme is specified, in the case of semantic versioning this would be ``semver`` or ``generic``. Following this a list of constraints divided by an ``|`` can be provided, to specify which versions are in scope.
A few examples:

To target all versions higher than and not including 2.0.0 the version range to provide would be::

    vers:generic/>2.0.0

To target all versions higher than and not including 2.0.0 that are also smaller than and including 4.5.0 the version range to provide would be::

    vers:generic/>2.0.0|<=4.5.0

To target all versions higher than and not including 2.0.0 that are also smaller than and including 4.5.0 except the single version 4.1.1 the version range to provide would be::

    vers:generic/>2.0.0|!=4.1.1|<=4.5.0

To target all versions to target all versions higher than and not including 2.0.0 that are also smaller than and including 4.5.0 as well as the additional version 5.0.0 the version range to provide would be::

    vers:generic/>2.0.0|<=4.5.0|5.0.0

Note that instead of specific version constraints it is possible to provide a wildcard *\** to allow all versions. So to target all versions the provided version range would be::

    vers:generic/*

Further information on the supported versions can be found here `univers documentation <https://pypi.org/project/univers/>`_.

If the target component isn't found in the SBOM, the program aborts with an error by default. This error can be downgraded to a warning using the ``--ignore-missing`` flag.

Protected fields
----------------

Some fields are protected and cannot be set by default. The full list of protected properties is:

- *cpe*
- *purl*
- *swid*
- *name*
- *group*
- *version*
- *components*

To set any of these fields, use the ``--allow-protected`` command-line switch.

Values
------

The *value* must be given as a valid JSON value. That means command-line usage can be a little strange, when setting a simple string value. To be valid JSON, the string must be surrounded by double quotes. Since double quotes hold a special meaning in most shells, they will likely have to be escaped. An example in the bash shell:

.. code:: bash

    # Set a simple string property, such as copyright in bash
    cdx-ev set bom.json --cpe <target-cpe> --key copyright --value '"2022 Acme Inc"'

    # Set the copyright for all versions of the given component
    cdx-ev set bom.json --group=org.acme --name=my_program --version-range vers:generic/* --key copyright --value '"Copyright 2024 Acme"'

Conflicts
---------

Conflicts arise when a target component already has a value for the specified property. When this happens, the command follows the following rules to determine how to proceed:

1. If the new value is ``null``, delete the existing property. The tool assumes that a user who sets ``null`` is aware that the property exists and wants to delete it.
2. If the property is an array, the new value is appended to the old value.
3. If the ``--ignore-existing`` command-line option is set, the old value will not be overwritten.
4. If the ``--force`` command-line option is set, the old value is overwritten with the new.
5. If the tool is running in an interactive terminal, the user is prompted to decide whether to overwrite the old value.
6. If none of the above applies, an error is thrown.

Hawk-eyed readers will have spotted a little stumbling block in these rules. What if an array should be overwritten? A little trickery is needed here. The property must first be explicitly deleted by setting it to ``null``, then re-added with the new value.
On the command-line this can be done in two subsequent invocations:

.. code:: bash

    # Overwrite an array-valued property
    cdx-ev set bom.json --cpe <target_cpe> --key licenses --value null
    cdx-ev set bom.json --cpe <target_cpe> --key licenses --value '[{"license": {"id": "MIT"}}]'

When passing the set list in a file, two separate updates must be specified for the same target component.

Set list file format
--------------------

When passing the targets, names and values in a file, the file must conform to this format::

    [
        {
            "id": {
                # Could be any one of the identifying properties in CycloneDX.
                # Multiple identifiers are not allowed (with the special exception of name,
                # group and version/version-range which are only valid together)
                "cpe": "CPE of target component goes here"
            },
            "set": {
                # Sets a simple property
                "copyright": "2022 Acme Inc",
                # Deletes a property
                "author": null,
                # Sets an array array-valued property. If the property already exists on the target,
                # the new value will be appended to the existing one.
                "licenses": [
                    {
                        "license": {
                            "id": "MIT"
                        }
                    }
                ]
            }
        },
        ...
    ]

Example for the use of version ranges::

    [
        {
            "id": {
                "name": "web-framework",
                "group": "org.acme",
                # It is possible to provide a version range
                # the format must comply with the PURL specification for version ranges
                "version-range": "vers:generic/>=1.0.2|<2.0.0",
            },
                "set": {"copyright": "1990 Acme Inc"},
        },
        {
            "id": {
                "name": "firmware-framework",
                "group": "org.acme",
                # It is also possible to provide a wildcard for the version
                # if the version is set to "*" all versions of the specified schema are passed
                "version-range": "vers:generic/*",
            },
                "set": {"copyright": "1990 Acme Inc"},
        },
        ...
    ]

The above provided example would set the `copyright` in the component ::

    {
        "name": "web-framework"
        "group": "org.acme",
        "version":"1.5.0"
    }

while it would leave the component ::

    {
        "name": "web-framework"
        "group": "org.acme",
        "version":"2.0.0"
    }

unchanged.

This file can then be applied as the following example shows:

.. code:: bash

    # Perform several operations on properties using set-command
    cdx-ev set bom.json --from-file mysetfile.json
