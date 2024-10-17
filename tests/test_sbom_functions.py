import unittest
from typing import Sequence

from cdxev.auxiliary import sbomFunctions as sbF
from cyclonedx.model.bom import Bom


class TestComponentFunctions(unittest.TestCase):
    def test_extract_components(self) -> None:
        example_list: Sequence[dict] = [
            {
                "bom-ref": "first_level_1",
                "components": [
                    {
                        "bom-ref": "second_level_1",
                    },
                    {
                        "bom-ref": "second_level_2",
                        "components": [
                            {
                                "bom-ref": "third_level_1",
                            },
                            {
                                "bom-ref": "third_level_2",
                            },
                        ],
                    },
                ],
            },
            {
                "bom-ref": "first_level_2",
                "components": [
                    {
                        "bom-ref": "second_level_3",
                        "components": [
                            {
                                "bom-ref": "third_level_3",
                                "components": [
                                    {
                                        "bom-ref": "fourth_level_1",
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "bom-ref": "second_level_4",
                    },
                ],
            },
            {
                "bom-ref": "first_level_3",
                "components": [
                    {
                        "bom-ref": "second_level_5",
                    }
                ],
            },
        ]
        components = sbF.extract_components(example_list)
        self.assertEqual(
            set(sbF.get_ref_from_components(components)),
            set(
                [
                    "first_level_1",
                    "first_level_2",
                    "first_level_3",
                    "second_level_1",
                    "second_level_2",
                    "second_level_3",
                    "second_level_4",
                    "second_level_5",
                    "third_level_1",
                    "third_level_2",
                    "third_level_3",
                    "fourth_level_1",
                ]
            ),
        )

    def test_extract_cyclonedx_components(self) -> None:
        example_list: Sequence[dict] = [
            {
                "name": "first_level_1",
                "bom-ref": "first_level_1",
                "components": [
                    {
                        "name": "second_level_1",
                        "bom-ref": "second_level_1",
                    },
                    {
                        "name": "second_level_2",
                        "bom-ref": "second_level_2",
                        "components": [
                            {
                                "name": "third_level_1",
                                "bom-ref": "third_level_1",
                            },
                            {
                                "name": "third_level_2",
                                "bom-ref": "third_level_2",
                            },
                        ],
                    },
                ],
            },
            {
                "name": "first_level_2",
                "bom-ref": "first_level_2",
                "components": [
                    {
                        "name": "second_level_3",
                        "bom-ref": "second_level_3",
                        "components": [
                            {
                                "name": "third_level_3",
                                "bom-ref": "third_level_3",
                                "components": [
                                    {
                                        "name": "fourth_level_1",
                                        "bom-ref": "fourth_level_1",
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "second_level_4",
                        "bom-ref": "second_level_4",
                    },
                ],
            },
            {
                "name": "first_level_3",
                "bom-ref": "first_level_3",
                "components": [
                    {
                        "name": "second_level_5",
                        "bom-ref": "second_level_5",
                    }
                ],
            },
        ]
        sbom_dict = {"components": example_list}
        sbom = sbF.deserialize(sbom_dict)
        components = sbF.extract_cyclonedx_components(sbom.components)
        bom_refs = []
        for component in components:
            bom_refs.append(component.bom_ref.value)
        self.assertEqual(
            set(bom_refs),
            set(
                [
                    "first_level_1",
                    "first_level_2",
                    "first_level_3",
                    "second_level_1",
                    "second_level_2",
                    "second_level_3",
                    "second_level_4",
                    "second_level_5",
                    "third_level_1",
                    "third_level_2",
                    "third_level_3",
                    "fourth_level_1",
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
