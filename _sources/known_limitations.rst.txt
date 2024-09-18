=================
Known Limitations
=================

- Only JSON-formatted SBOMs are supported. XML support is not planned.
- Though validation is supported it's not used before execute an operation. Unforeseen errors might occur if an invalid CycloneDX is fed as input. Users are encouraged to use either a stock CycloneDX validator or the validation of this tool beforehand, depending on whether the input/output is meant to conform to a specific specification or not.
- *git bash* is known to cause problems with interactive user input. The *set* command won't prompt the user whether to overwrite conflicting information in *git bash*.
