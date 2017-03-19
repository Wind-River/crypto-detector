"""
Copyright (c) 2017 Wind River Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.
"""

import os
import time
import hashlib
import codecs
from unittest import TestCase
from cryptodetector import Options, CryptoDetector, MethodFactory

class TestCryptoDetector(TestCase):
    """Unit Tests
    """

    KNOWN_TEST_SHA1 = "370aef2687f5d68f3696b0190d459600a22dccf7"

    def method(self, method_id):
        for mc in MethodFactory.method_classes:
            if mc.method_id == method_id:
                return mc

    def scan_package(self, test_packages, extra_options={}, keyword_ignore_case=True):

        options = Options()._get_options()
        for option in extra_options:
            options[option] = extra_options[option]

        current_directory = os.path.dirname(os.path.abspath(__file__))
        options["packages"] = []
        for package in test_packages:
            package_full_path = os.path.join(current_directory, package)
            options["packages"].append(package_full_path)

        self.method("keyword").options["kwlist_path"] = os.path.join(current_directory, \
            "test_keyword_list.conf")

        self.method("keyword").options["ignore_case"] = keyword_ignore_case

        self.method("api").options["kwlist_path"] = os.path.join(current_directory, \
            "test_api_list.conf")

        return CryptoDetector(options, skip_output=True).scan()

    def sha1(self, file_full_path):
        with open(file_full_path) as f:
            checksum_calculator = hashlib.sha1()
            checksum_calculator.update(codecs.encode(f.read(), "utf-8"))
            return checksum_calculator.hexdigest()

    def count_matches(self, data, package, file, evidence_type, package_name=None, known_sha1=None):
        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, package)
        file_full_path = os.path.abspath(os.path.join(file_full_path, file))
        if known_sha1 is None:
            file_sha1 = self.sha1(file_full_path)
        else:
            file_sha1 = known_sha1

        if package_name is None:
            package_name = package

        self.assertTrue(file_sha1 in data[package_name]["crypto_evidence"])

        count = 0
        for match in data[package_name]["crypto_evidence"][file_sha1]["hits"]:
            if match["evidence_type"] == evidence_type:
                count += 1
        return count

    def assert_result_not_empty(self, result, package):
        self.assertTrue(package in result)
        self.assertTrue("crypto_evidence" in result[package])
        self.assertTrue(result[package]["crypto_evidence"] != {})

    def archive_test(self, archive_type):
        result = self.scan_package(["extract_test/test." + archive_type], \
            {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "test." + archive_type)
        self.assertEqual(self.count_matches(result, "extract_test/test." + archive_type \
            , "test", "keyword_boundary_all", "test." + archive_type, \
            known_sha1=self.KNOWN_TEST_SHA1), 40)

    def get_testpkg3_matches(self):
        result = self.scan_package(["testpkg3"], {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "testpkg3")
        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, "testpkg3")
        file_full_path = os.path.join(file_full_path, "test")
        file_sha1 = self.sha1(file_full_path)
        self.assertTrue(file_sha1 in result["testpkg3"]["crypto_evidence"])
        matches = result["testpkg3"]["crypto_evidence"][file_sha1]["hits"]
        self.assertEqual(len(matches), 3)
        return matches

    def test_match_boundary(self):
        result = self.scan_package(["testpkg1"], {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "testpkg1")
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_any"), \
            60)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_begin"), \
            48)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_end"), \
            48)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_all"), \
            40)

    def test_keyword_ignore_case(self):
        result = self.scan_package(["testpkg1"], {"methods": ["keyword"]}, keyword_ignore_case=False)
        self.assert_result_not_empty(result, "testpkg1")
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_any"), \
            45)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_begin"), \
            36)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_end"), \
            36)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_all"), \
            30)

    def test_multiple_packages(self):
        result = self.scan_package(["testpkg1", "testpkg3"], {"methods": ["keyword"]})

        self.assert_result_not_empty(result, "testpkg1")
        self.assert_result_not_empty(result, "testpkg3")

    def test_extract_zip(self):
        self.archive_test("zip")

    def test_extract_tar_bz2(self):
        self.archive_test("tar.bz2")

    def test_extract_tar_xz(self):
        self.archive_test("tar.xz")

    def test_extract_tar_gz(self):
        self.archive_test("tar.gz")

    def test_extract_tar_lzma(self):
        self.archive_test("tar.lzma")

    def test_extract_rpm(self):
        self.archive_test("rpm")

    def test_extract_jar(self):
        self.archive_test("jar")

    def test_extract_tar(self):
        self.archive_test("tar")

    def test_extract_war(self):
        self.archive_test("war")

    def test_extract_gz(self):
        self.archive_test("gz")

    def test_extract_bz2(self):
        self.archive_test("bz2")

    def test_extract_xz(self):
        self.archive_test("xz")

    def test_extract_lzma(self):
        self.archive_test("lzma")

    def test_extract_recursive_archives(self):
        result = self.scan_package(["extract_test/recursive.zip"], \
            {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "recursive.zip")
        self.assertEqual(self.count_matches(result, "extract_test/recursive.zip/test.gz", \
            "test", "keyword_boundary_all", "recursive.zip", \
            known_sha1=self.KNOWN_TEST_SHA1), 120)

    def test_ignore_evidence_types(self):
        result = self.scan_package(["testpkg1"], {"methods": ["keyword"], \
            "ignore_evidence_types": ["keyword_any", "keyword_boundary_end"]})
        self.assert_result_not_empty(result, "testpkg1")
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_any"), \
            0)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_begin"), \
            48)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_end"), \
            0)
        self.assertEqual(self.count_matches(result, "testpkg1", "file1", "keyword_boundary_all"), \
            40)

    def test_stop_after(self):
        result = self.scan_package(["testpkg1"], {"methods": ["keyword"], "stop_after": 2})
        self.assert_result_not_empty(result, "testpkg1")
        self.assertEqual(len(result["testpkg1"]["crypto_evidence"]), 2)

        result = self.scan_package(["testpkg1"], {"methods": ["keyword"], "stop_after": 1})
        self.assert_result_not_empty(result, "testpkg1")
        self.assertEqual(len(result["testpkg1"]["crypto_evidence"]), 1)

    def test_source_files_only(self):
        result = self.scan_package(["testpkg1"], {"methods": ["keyword"], "source_files_only": True})
        self.assert_result_not_empty(result, "testpkg1")
        self.assertEqual(len(result["testpkg1"]["crypto_evidence"]), 1)

        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, "testpkg1")
        file_full_path = os.path.abspath(os.path.join(file_full_path, "file.cpp"))
        file_sha1 = self.sha1(file_full_path)

        self.assertTrue(file_sha1 in result["testpkg1"]["crypto_evidence"])

    def test_no_matches(self):
        result = self.scan_package(["testpkg2"], {"methods": ["keyword"]})
        self.assertTrue("testpkg2" in result)
        self.assertTrue("crypto_evidence" in result["testpkg2"])
        self.assertTrue(result["testpkg2"]["crypto_evidence"] == {})

    def test_line_text(self):
        for match in self.get_testpkg3_matches():
            if match["evidence_type"] == "keyword_any":
                self.assertEqual(match["line_text"], "testtestloremtesttest")

            elif match["evidence_type"] == "keyword_boundary_begin":
                self.assertEqual(match["line_text"], "testtest IPSUM test")

            elif match["evidence_type"] == "keyword_boundary_end":
                self.assertEqual(match["line_text"], "test dolor")

    def test_file_index(self):
        for match in self.get_testpkg3_matches():
            if match["evidence_type"] == "keyword_any":
                self.assertEqual(match["file_index_begin"], 8)
                self.assertEqual(match["file_index_end"], 13)

            elif match["evidence_type"] == "keyword_boundary_begin":
                self.assertEqual(match["file_index_begin"], 41)
                self.assertEqual(match["file_index_end"], 46)

            elif match["evidence_type"] == "keyword_boundary_end":
                self.assertEqual(match["file_index_begin"], 67)
                self.assertEqual(match["file_index_end"], 72)

    def test_line_index(self):
        for match in self.get_testpkg3_matches():
            if match["evidence_type"] == "keyword_any":
                self.assertEqual(match["line_index_begin"], 8)
                self.assertEqual(match["line_index_end"], 13)

            elif match["evidence_type"] == "keyword_boundary_begin":
                self.assertEqual(match["line_index_begin"], 9)
                self.assertEqual(match["line_index_end"], 14)

            elif match["evidence_type"] == "keyword_boundary_end":
                self.assertEqual(match["line_index_begin"], 5)
                self.assertEqual(match["line_index_end"], 10)

    def test_line_number(self):
        for match in self.get_testpkg3_matches():
            if match["evidence_type"] == "keyword_any":
                self.assertEqual(match["line_number"], 1)

            elif match["evidence_type"] == "keyword_boundary_begin":
                self.assertEqual(match["line_number"], 4)

            elif match["evidence_type"] == "keyword_boundary_end":
                self.assertEqual(match["line_number"], 7)

    def test_matched_text(self):
        for match in self.get_testpkg3_matches():
            if match["evidence_type"] == "keyword_any":
                self.assertEqual(match["matched_text"], "lorem")

            elif match["evidence_type"] == "keyword_boundary_begin":
                self.assertEqual(match["matched_text"], "IPSUM")

            elif match["evidence_type"] == "keyword_boundary_end":
                self.assertEqual(match["matched_text"], "dolor")
