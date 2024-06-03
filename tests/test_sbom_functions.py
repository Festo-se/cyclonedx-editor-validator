import unittest
from typing import Sequence

from cdxev.auxiliary import sbomFunctions as sbF


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


if __name__ == "__main__":
    unittest.main()