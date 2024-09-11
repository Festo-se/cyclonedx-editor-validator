============
build-public
============

.. argparse::
    :filename: ./cdxev/__main__.py
    :func: create_parser
    :prog: cdx-ev
    :path: build-public

    This command creates a redacted version of an SBOM fit for publication. It:

    * can optionally delete entire components matching a JSON schema provided by the user, and it
    * deletes any *property* (i.e., item in the ``properties`` array of a component) whose name starts with ``internal:`` from all components.

    The actions are performed in this order, meaning that *internal* properties will be taken into account when matching the JSON schema.
    If a component containing nested components is deleted, those nested components are deleted as well.

    The JSON schema must be formulated according to the Draft 7 specification.

Dependency-resolution
---------------------

Any components deleted by this command are equally removed from the dependency graph. Their dependencies are assigned as new dependencies to their dependents.

.. image:: /img/dependency-resolution.svg
    :alt: Dependencies of deleted components are assigned to their dependents.

Examples
--------

Here are some JSON schemata for common scenarios to get you started.

When passed to the command, this schema will remove any component whose ``group`` is ``com.acme.internal``::

    {
        "properties": {
            "group": {
                "const": "com.acme.internal"
            }
        },
        "required": ["group"]
    }

An extension of the above, the next schema will delete any component with that ``group``, *unless* it contains a property with the name ``internal:public`` and the value ``true``. *Note that the property itself will still be removed from the component, because its name starts with* ``internal:``.
::

    {
        "properties": {
            "group": {
                "const": "com.acme.internal"
            }
        },
        "required": ["group"],
        "not": {
            "properties": {
                "properties": {
                    "contains": {
                        "properties": {
                            "name": {
                                "const": "internal:public"
                            },
                            "value": {
                                "const": "true"
                            }
                        },
                        "required": ["name", "value"]
                    }
                }
            },
            "required": ["properties"]
        }
    }

This schema will delete the three components with the names ``AcmeSecret``, ``AcmeNotPublic`` and ``AcmeSensitive``::

    {
        "properties": {
            "name": {
                "enum": ["AcmeSecret", "AcmeNotPublic", "AcmeSensitive"]
            }
        },
        "required": ["name"]
    }

The following schema is a little more involved. It will delete any component whose license text contains the string ``This must not be made public``::

    {
        "properties": {
            "licenses": {
                "contains": {
                    "properties": {
                        "license": {
                            "properties": {
                                "text": {
                                    "properties": {
                                        "content": {
                                            "pattern": "This must not be made public"
                                        }
                                    }
                                }
                            },
                            "required": ["text"]
                        }
                    },
                    "required": ["license"]
                }
            }
        },
        "required": ["licenses"]
    }
