# Available commands

This section only covers the commands where further information is required. For all commands use

    cdx-ev --help              # Lists commands and options

Before use, please consider the [known limitations](https://festo-se.github.io/cyclonedx-editor-validator/known_limitations/) of the tool.

## amend

This command accepts a single input file and will apply one or multiple *operations* to it. Each operation modifies certain aspects of the SBOM. These modifications cannot be targeted at individual components in the SBOM which sets the *amend* command apart from *set*. Its use-case is ensuring an SBOM fulfils certain requirements in an automated fashion.

See the command help with `cdx-ev amend --help` for a list of available operations. All operations marked `[default]` will run unless the command-line option `--operation` is provided.

For more information on a particular operation, use the `cdx-ev amend --help-operation <operation>` command.

Note that the order of operations cannot be controlled. If you want to ensure two operations run in a certain order you must run the command twice, each time with a different set of operations.

__Example:__

    # Run all default operations on an SBOM.
    cdx-ev amend bom.json

    # Run only the default-author and add-bom-ref operations.
    cdx-ev amend --operation default-author --operation add-bom-ref bom.json

    # Run the add-license-text operation. License texts are stored in a directory named 'license_texts'.
    # Afterwards, run the delete-ambiguous-licenses operation.
    cdx-ev amend --operation add-license-text --license-dir ./license_texts bom.json --output bom.json
    cdx-ev amend --operation delete-ambiguous-licenses bom.json

### Operations

This section details the more complex operations which require further explanation beyond the help text provided by `--help-operation <operation>`.

#### add-license-text

The operation `add-license-text` can be used to insert known full license texts for licenses identified by name. You can use this, for instance, in workflows where SBOMs are created or edited by hand - so a clutter-free JSON is preferred - then, in a last step, full texts are inserted using this operation.

License texts are inserted only if:

* The license has a `name` field.
* The license has no `id` field.
* The license has no or an empty `text.content` field.
* A matching file is found.

You must provide one file per license text in a flat directory. The stem of the filename, that is everything up to the extension (i.e., up to but not including the last period), must match the license name specified in the SBOM.

__Example:__

Given this license in the input SBOM:

    {
        "license": {
            "name": "My license"
        }
    }

the operation would search the full license text in any file named `My license`, `My license.txt`, `My license.md`, or any other extension.
However, the file `My license.2.txt` would be disregarded, because its stem (`My license.2`) doesn't match the license name.

## build-public

This command creates a redacted version of an SBOM fit for publication. It

* can optionally delete entire components matching a JSON schema provided by the user, and it
* deletes any *property* (i.e., item in the `properties` array of a component) whose name starts with `internal:` from all components.

The actions are performed in this order, meaning that *internal* properties will be taken into account when matching the JSON schema.

The JSON schema must be formulated according to the Draft 7 specification.

### Dependency-resolution

Any components deleted by this command are equally removed from the dependency graph. Their dependencies are assigned as new dependencies to their dependents.

![Dependencies of deleted components are assigned to their dependents.](img/dependency-resolution.svg)

### Examples

Here are some JSON schemata for common scenarios to get you started.

When passed to the command, this schema will remove any component whose `group` is `com.acme.internal`.

    {
        "properties": {
            "group": {
                "const": "com.acme.internal"
            }
        },
        "required": ["group"]
    }

An extension of the above, the next schema will delete any component with that `group`, __unless__ it contains a property with the name `internal:public` and the value `true`.
*Note that the property itself will still be removed from the component, because its name starts with `internal:`.*

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

This schema will delete the three components with the names `AcmeSecret`, `AcmeNotPublic` and `AcmeSensitive`:

    {
        "properties": {
            "name": {
                "enum": ["AcmeSecret", "AcmeNotPublic", "AcmeSensitive"]
            }
        },
        "required": ["name"]
    }

The following schema is a little more involved. It will delete any component whose license text contains the string `This must not be made public`.

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

## merge

This command requires at least two input files, but can accept an arbitrary number.

Alternatively only one file can be submitted and the command `--from-folder` must be used to provide the path to a folder.
This command reads the contents of the provided folder and loads *all files* with "*.cdx.json" or the name "bom.json", according to the naming convention described in the [CycloneDX Specification](https://cyclonedx.org/specification/overview/#recognized-file-patterns).
If a file in the folder has the same name as the provided sbom to be merged in, it will be skipped.
The files are then merged in alphabetical order into the regularly provided sbom in this order.

The process runs iterative, merging two SBOMs in each step.
In the first step, the second submitted SBOM is merged into the first.
In the second step the third would be merged into the resulting SBOM from step one etc.

The Resulting SBOM will contain the Metadata from the first SBOM submitted, with only the timestamp being updated.

The components from the first SBOM submitted will be kept unchanged, if the SBOMs that are merged contain new components,
those will be added to the list of components. Should a component be contained in several SBOMs, the one from the SBOM that was merged earlier will be taken without any consideration. If this happens and a component is dropped during the merge, a warning will be shown.
Uniqueness of the bom-refs will be ensured.

The dependencies for new components are taken over.
If components are contained in both SBOMs, then the dependsON lists
for them will be merged so that no information will be lost.

If a VEX section is contained, it will be merged as well, for details see merge-vex section

## merge-vex

[Deprecated] - The `merge-vex` command will be superseded by a new `vex` command in a future version. For further information refer to the [discussion](https://github.com/Festo-se/cyclonedx-editor-validator/issues/156#issuecomment-2058312043).

This command requires two input files, a SBOM and a VEX file that shell be merged.
The VEX file needs to be compatible with the SBOM.

If the SBOM does not contain a VEX file, the VEX file simply be added to the SBOM.

If the SBOM already contains a VEX section, the two VEX files are merged uniquely.
In the case of duplicate entries, the ratings will be merged. Should two ratings
of the same method contain a different rating, the newer one will be kept.

## set

This command sets properties on specified components to specified values. If a component in an SBOM is missing a particular property or the property is present but has a wrong value, this command can be used to modify just the affected properties without changing the rest of the SBOM.

For this command to work, three bits of information must be provided by the user: The __target__ component(s) to modify as well as the __name__ and __new value__ of each property to set on the target component.

This data can either be passed directly on the command-line &mdash; in this case only a single update can be performed per invocation &mdash; or in a JSON file &mdash; this allows performing an unlimited number of updates in a single invocation.

### Target components

The *target component* can be identified through any of the identifiable properties defined by CycloneDX, specifically: *cpe*, *purl*, *swid* or the combination of *name*, *group* and/or *version* (collectively called *coordinates*).

If *coordinates* are used to identify the target, they must match the component fully. In other words, if __only__ *name* is given, it will __only match__ components with that name which do __not__ contain *version* or *group* fields.

If the target component isn't found in the SBOM, the program aborts with an error by default. This error can be downgraded to a warning using the `--ignore-missing` flag.

#### Protected fields

Some fields are protected and cannot be set by default. The full list of protected properties is:

* *cpe*
* *purl*
* *swid*
* *name*
* *group*
* *version*
* *components*

To set any of these fields, use the `--allow-protected` command-line switch.

### Values

The *value* must be given as a valid JSON value. That means command-line usage can be a little strange, when setting a simple string value. To be valid JSON, the string must be surrounded by double quotes. Since double quotes hold a special meaning in most shells, they will likely have to be escaped. An example for bash follows.

    # Set a simple string property, such as copyright in bash
    cdx-ev set bom.json --cpe <target-cpe> --key copyright --value '"2022 Acme Inc"'

### Conflicts

Conflicts arise when a target component already has a value for the specified property. When this happens, the command follows the following rules to determine how to proceed:

1. If the new value is `null`, delete the existing property. The tool assumes that a user who sets `null` is aware that the property exists and wants to delete it.
2. If the property is an array, the new value is appended to the old value.
3. If the `--force` command-line option is set, the old value is overwritten with the new.
4. If the tool is running in an interactive terminal, the user is prompted to decide whether to overwrite the old value.
5. If none of the above applies, an error is thrown.

Hawk-eyed readers will have spotted a little stumbling block in these rules. What if an array should be overwritten? A little trickery is needed here. The property must first be explicitly deleted by setting it to `null`, then re-added with the new value.
On the command-line this can be done in two subsequent invocations:

    # Overwrite an array-valued property
    cdx-ev set bom.json --cpe <target_cpe> --key licenses --value null
    cdx-ev set bom.json --cpe <target_cpe> --key licenses --value '[{"license": {"id": "MIT"}}]'

When passing the set list in a file, two separate updates must be specified for the same target component.

### Set list file format

When passing the targets, names and values in a file, the file must conform to this format:

    [
        {
            "id": {
                # Could be any one of the identifying properties in CycloneDX.
                # Multiple identifiers are not allowed (with the special exception of name,
                # group and version which are only valid together)
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

This file can then be applied as the following example shows:

    # Perform several operations on properties using set-command
    cdx-ev set bom.json --from-file mysetfile.json

If the file contains a component not present in the SBOM, a error is thrown.
This can be disabled with the `--ignore-missing` command.
So only a message that the component was not found and could not be updated is logged.

    cdx-ev set bom.json --from-file mysetfile.json --ignore-missing

#### set for version ranges

To perform set on a range of versions "name", "version" and, if it exists, group have to be used as "id".
The version constraints can then be specified with a list of single versions or with the use of the order operators >, <, >=, <=,
and be separated with a |. An example for a version range string would be ">1.1.1|<1.5.6|2.0.0".

It is also possible to use a wildcard with "\*". So would "\*" include all versions and "1.\*" all versions that begin with "1.".
This can be combined with constraints using order operators. The wildcard applies to everything following the designated position (i.e. (.)*).

The program is able to parse versions following the MAJOR.MINOR.PATCH schema matching the regular expression "\[N!\]N(.N)\*\[{a|b|rc}N\]\[.postN\]\[.devN\]", for other version schemas see upload of custom versions.

An example for a update file with version ranges:  

    [
        {
            "id": {
                "name": "web-framework",
                "group": "org.acme",
                "version": "<3.0.0|>3.2.0|<4.0.0|5.0.0",
            },
            "set": {"copyright": "1990 Acme Inc"},
        },
        {
            "id": {
                "name": "embedded-framework",
                "group": "org.acme",
                "version": "2.*|<2.5.8",
            },
            "set": {"copyright": "2000 Acme Inc"},
        },
    ]

##### Uploading of own versions

It is possible to upload lists of custom software versions the program can then parse and perform set with version ranges on it.
For this use the `--custom-versions` command to provide the path to file containing the versions.

The file has to follow the format:

    [
        {
            "version_schema": "some identifier",
            "version_list":[
            version 1,
            version 2,
            version 3
            ]
        },
        {
            "version_schema": "some other identifier",
            "version_list":[
            first version,
            second version,
            third version
            ]
        }
    ]

The order of the versions has to be aligned with their index in the list.

## validate

This command is used to validate the SBOM against a JSON schema.

### Schema selection

This tool can validate SBOMs against any user-provided JSON schema but for convenience, two schema types are built in:

* The *default* schema type validates against the [stock CycloneDX schema](https://github.com/CycloneDX/specification).
* The *custom* schema type uses a more restrictive schema which accepts a subset of CycloneDX. Additional requirements incorporated into the schema mostly originate from the [NTIA](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf).

You can select the schema with the `--schema-type` and `--schema-path` options:

    cdx-ev validate bom.json [--schema-type default]           # stock CycloneDX schema
    cdx-ev validate bom.json --schema-type custom              # built-in custom schema
    cdx-ev validate bom.json --schema-path <json_schema.json>  # your own schema

For all built-in schemas, the tool attempts to determine the correct CycloneDX version from the input SBOM and falls back to version 1.3 if that fails. The following versions are currently supported:

| Type | Supported CycloneDX versions |
| ---- | ---------------------------- |
| `default` | 1.2 to 1.5 |
| `custom` | 1.3 to 1.5 |

### Validation of filename

The tool, by default, also validates the filename of the SBOM. Which filenames are accepted depends on several command-line options:

* `--no-filename-validation` completely disables validation.
* Use `--filename-pattern` to provide a custom regex. The filename must be a full match, regex anchors (^ and $) are not required. Regex patterns often include special characters. Pay attention to escaping rules for your shell to ensure proper results.
* In all other cases, the acceptable filenames depend on the selected schema:
  * When using the stock CycloneDX schema (`--schema-type default` or no option at all) or when using your own schema (`--schema-path` option), the validator accepts the two patterns recommended by the [CycloneDX specification](https://cyclonedx.org/specification/overview/#recognized-file-patterns): `bom.json` or `*.cdx.json`.
  * When validating against the built-in custom schema (`--schema-type custom`), filenames must match one of these patterns: `bom.json` or `<name>_<version>_<hash>|<timestamp>|<hash>_<timestamp>.cdx.json`. Read on for some clarifications.

`<name>` and `<version>` correspond to the respective fields in `metadata.component` in the SBOM.

`<timestamp>` corresponds to `metadata.timestamp` and `<hash>` means any value in `metadata.component.hashes[].content`.  
Either *timestamp* or *hash* must be present. If both are specified, *hash* must come first.

### Output

By default, the command writes human-readable validation results to *stderr* only. For integration into CI/CD several machine-readable report formats are supported as well. To have a report written to a file, select the format using the `--report-format` option and an output path using the `--report-path` option.

These formats are currently supported:

* [Jenkins warnings-ng-plugin](https://github.com/jenkinsci/warnings-ng-plugin)
* [GitLab Code Quality](https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool)

Examples:

    # Write human-readable messages to stderr and a report in warnings-ng format to report.json
    cdx-ev validate bom.json --report-format warnings-ng --report-path report.json

    # Write only a report in GitLab Code Quality format to cq.json
    cdx-ev --quiet validate bom.json --report-format gitlab-code-quality --report-path cq.json
