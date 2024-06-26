import cdxev.create_notice_file as NoticeFile
import json
import unittest

path_to_sbom = (
    "tests/auxiliary/test_create_notice_file_sboms/"
    "Acme_Application_9.1.1_20220217T101458.cdx.json"
)


def get_test_sbom(pathsbom: str = path_to_sbom) -> dict:
    with open(pathsbom, "r") as read_file:
        sbom = json.load(read_file)
    return sbom


class TestCreateNoticeFile(unittest.TestCase):

    def test_extract_license(self) -> None:
        sbom = get_test_sbom()
        print(NoticeFile.create_notice_file(sbom))
        