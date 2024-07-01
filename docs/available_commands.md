# Available commands

This section only covers the commands where further information is required. For all commands use

    cdx-ev --help              # Lists commands and options

Before use, please consider the [known limitations](https://festo-se.github.io/cyclonedx-editor-validator/known_limitations/) of the tool.

## amend

This command accepts a single input file and will apply one or multiple *operations* to it. Each operation modifies certain aspects of the SBOM. These modifications cannot be targeted at individual components in the SBOM which sets the *amend* command apart from *set*. It's use-case is ensuring an SBOM fulfils certain requirements in an automated fashion.

See the command help with `cdx-ev amend --help` for a list of available operations. All operations marked `[default]` will run unless the command-line option `--operation` is provided.

For more information on a particular operation, use the `cdx-ev amend --help-operation <operation>` command.

Note that the order of operations cannot be controlled. If you want to ensure two operations run in a certain order you must run the command twice, each time with a different set of operations.

### Copy license texts from files

The program can copy the text describing a license from a specific file into the SBOM, if a license name is given.

This is done by submitting the path to a folder containing txt-files with the license text via the command `--license-path`.
If for example the license name "Apache License 1.0" is given, the program will search in the provided folder for the file "Apache License 1.0.txt" and copy its content in the `text` field.
The txt-files in the folder must follow the naming convention name.txt.

    cdx-ev amend bom.json" --license-path=C:\Documents\licenses

If a `text` field already exists, its content will be replaced.

## merge

This command requires at least two input files, but can accept an arbitrary number. Inputs can either be specified directly as positional arguments on the command-line or using the `--from-folder <path>` option. Files specified as arguments are merged in the order they are given, files in the folder are merged in alphabetical order (see note below).  
If both positional arguments and the `--from-folder` option are used, then the position arguments are merged first, followed by the files in the folder. The command will not merge the same file twice, if it is specified on the command-line and also part of the folder.

When using the `--from-folder` option, the program looks for files matching either of the [recommended CycloneDX naming schemes](https://cyclonedx.org/specification/overview/#recognized-file-patterns): `bom.json` or `*.cdx.json`.

__Note on merge order:__  
Input files in the folder provided to the `--from-folder` option are sorted in a platform-specific way. In other words, they are merged in the same order they appear in your operating system's file browser (e.g., Windows Explorer).

The process runs iteratively, merging two SBOMs in each iteration. In the first round, the second submitted SBOM is merged into the first. In the second round the third would be merged into the result of the first round and so on.  
In mathematical terms: `output = (((input_1 x input_2) x input_3) x input_4 ...)`

A few noted on the merge algorithm:

* The `metadata` field is always retained from the first input and never changed through a merge with the exception of the `timestamp`.
* Components are merged into the result in the order they __first__ appear in the inputs. If any subsequent input specifies the same component (sameness in this case being defined as having identical identifying attributes such as `name`, `version`, `purl`, etc.), the later instance of the component will be dropped with a warning. __This command cannot be used to merge information inside components.__
* The resulting dependency graph will reflect all dependencies from all inputs. Dependencies from later inputs are always added to the result, even if the component is dropped as a duplicate as described above.
* Uniqueness of *bom-refs* will be ensured.
* If the inputs contain VEX information in the form of a `vulnerabilities` field, this will be merged as well. For details see section on the `merge-vex` command.

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

## validate

This command is used to validate the SBOM according to a specification.

### Use of different schemas

The package is currently delivered with the specification for CycloneDX 1.3 and 1.4. Further, it is provided with a custom schema, which not only requires the minimum elements as defined by the [NTIA](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) but also some further recommended fields, e.g. licenses and stating the known unknowns (through the `compositions`-field).
You can control the usage of the specification with the flag `--schema-type`:

    cdx-ev validate bom.json --schema-type=custom # use provided custom schema in package
    cdx-ev validate bom.json # default CycloneDX specification will be used

### Use of local schema

With the `--schema-path` flag, users can supply their own schema to the validator.

    cdx-ev validate bom.json --schema-path=C:\users\documents\sbom_schemas\example_schema.json  # uses a schema "example_schema.json" saved on the users computer to verify the sbom

### Validation of filename

The tool, by default, also validates the filename of the SBOM. Which filenames are accepted depends on several command-line options:

* `--no-filename-validation` completely disables validation.
* Use `--filename-pattern` to provide a custom regex. The filename must be a full match, regex anchors (^ and $) are not required. Regex patterns often include special characters. Pay attention to escaping rules for your shell to ensure proper results.
* In all other cases, the acceptable filenames depend on the `--schema-type` option:
  * Using the `default` schema (i.e., vanilla CycloneDX), the validator accepts the two patterns recommended by the [CycloneDX specification](https://cyclonedx.org/specification/overview/#recognized-file-patterns): `bom.json` or `*.cdx.json`.
  * Using the `custom` schema, filenames must match one of these patterns: `bom.json` or `<name>_<version>_<hash>|<timestamp>|<hash>_<timestamp>.cdx.json`. Read on for some clarifications.

`<name>` and `<version>` correspond to the respective fields in `metadata.component` in the SBOM.

`<timestamp>` corresponds to `metadata.timestamp` and `<hash>` means any value in `metadata.component.hashes[].content`.  
Either *timestamp* or *hash* must be present. If both are specified, *hash* must come first.

### Logging

Per default the command only writes to stdout. However, for supporting integration into CI/CD, other formats shall be supported, too. This can be controlled via the flag `--report-format`.

Currently, two formats are supported: The [warnings-ng-plugin](https://github.com/jenkinsci/warnings-ng-plugin) and [GitLab Code Quality Report](https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool). They can be used as followed:

    cdx-ev validate bom.json --report-format=warnings-ng" # writes issues to a file "issues.json" and stdout
    cdx-ev validate bom.json --report-format=warnings-ng --output=myfile.json" # write issues to a file "myfile.json" and stdout
    cdx-ev validate bom.json --report-format=gitlab-code-quality # writes issues to a file "issues.json" and stdout

## build-public

This command creates a reduced version of an SBOM fit for publication. It:

* deletes components matching a JSON schema provided by the user, and
* removes any *property* (i.e., item in the `properties` array of a component) whose name starts with `internal:` from all components.

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
