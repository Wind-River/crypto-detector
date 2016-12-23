"""
Copyright (c) 2016 Wind River Systems, Inc.

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
from unittest import TestCase
from cryptodetector import Options, CryptoDetector, MethodFactory

class TestCryptoDetector(TestCase):
    """Unit Tests
    """

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
            "dummy_keyword_list.conf")

        self.method("keyword").options["ignore_case"] = keyword_ignore_case

        self.method("api").options["kwlist_path"] = os.path.join(current_directory, \
            "dummy_api_list.conf")

        return CryptoDetector(options, skip_output=True).scan()

    def count_matches(self, data, package, file, match_type, package_name=None):
        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, package)
        file_full_path = os.path.abspath(os.path.join(file_full_path, file))

        if package_name is None:
            package_name = package

        self.assertTrue(file_full_path in data[package_name]["report"])

        count = 0
        for match in data[package_name]["report"][file_full_path]["matches"]:
            if match["match_type"] == match_type:
                count += 1
        return count

    def assert_result_not_empty(self, result, package):
        self.assertTrue(package in result)
        self.assertTrue("report" in result[package])
        self.assertTrue(result[package]["report"] != {})

    def archive_test(self, archive_type):
        result = self.scan_package(["extract_test/test." + archive_type], \
            {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "test." + archive_type)
        self.assertEqual(self.count_matches(result, "extract_test/test." + archive_type \
            , "test", "keyword_boundary_all", "test." + archive_type), 40)

    def archive_test_tar(self, archive_type):
        """For some reason, sometimes, FileLister extracts tar archives to .tar and then
        to its files, and sometimes directly to its files."""
        result = self.scan_package(["extract_test/test." + archive_type], \
            {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "test." + archive_type)

        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, "extract_test/test." + archive_type)
        tar_file_full_path = os.path.join(file_full_path, "test.tar")
        file_full_path = os.path.abspath(os.path.join(file_full_path, "test"))
        tar_file_full_path = os.path.abspath(os.path.join(tar_file_full_path, "test"))

        file_path_exists = file_full_path  in result["test." + archive_type]["report"]
        tar_path_exists = tar_file_full_path in result["test." + archive_type]["report"]

        self.assertTrue(file_path_exists or tar_path_exists)

        if file_path_exists:
            self.assertEqual(self.count_matches(result, "extract_test/test." + archive_type \
             , "test", "keyword_boundary_all", "test." + archive_type), 40)
        else:
            self.assertEqual(self.count_matches(result, "extract_test/test." \
                +  archive_type + "/test.tar", "test", "keyword_boundary_all", "test." +
                archive_type), 40)

    def get_dummy2_matches(self):
        result = self.scan_package(["dummy", "dummy2"], {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "dummy2")
        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, "dummy2")
        file_full_path = os.path.join(file_full_path, "test")
        self.assertTrue(file_full_path in result["dummy2"]["report"])
        matches = result["dummy2"]["report"][file_full_path]["matches"]
        self.assertEqual(len(matches), 3)
        return matches

    def test_match_boundary(self):
        result = self.scan_package(["dummy"], {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "dummy")
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_any"), \
            60)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_begin"), \
            48)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_end"), \
            48)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_all"), \
            40)

    def test_keyword_ignore_case(self):
        result = self.scan_package(["dummy"], {"methods": ["keyword"]}, keyword_ignore_case=False)
        self.assert_result_not_empty(result, "dummy")
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_any"), \
            45)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_begin"), \
            36)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_end"), \
            36)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_all"), \
            30)

    def test_multiple_packages(self):
        result = self.scan_package(["dummy", "dummy2"], {"methods": ["keyword"]})
        self.assert_result_not_empty(result, "dummy")
        self.assert_result_not_empty(result, "dummy2")

    def test_checksum(self):
        result = self.scan_package(["dummy"], {"methods": ["keyword"]})
        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, "dummy")
        file_full_path = os.path.abspath(os.path.join(file_full_path, "file1"))

        self.assertEqual(result["dummy"]["report"][file_full_path]["SHA1_checksum"], \
            "370aef2687f5d68f3696b0190d459600a22dccf7")

    def test_extract_zip(self):
        self.archive_test("zip")

    def test_extract_tar_bz2(self):
        self.archive_test_tar("tar.bz2")

    def test_extract_tar_gz(self):
        self.archive_test_tar("tar.gz")

    def test_extract_tar_lzma(self):
        self.archive_test_tar("tar.lzma")

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
            "test", "keyword_boundary_all", "recursive.zip"), 40)
        self.assertEqual(self.count_matches(result, "extract_test/recursive.zip/test.bz2", \
            "test", "keyword_boundary_all", "recursive.zip"), 40)
        self.assertEqual(self.count_matches(result, "extract_test/recursive.zip/test.zip", \
            "test", "keyword_boundary_all", "recursive.zip"), 40)

    def test_ignore_match_types(self):
        result = self.scan_package(["dummy"], {"methods": ["keyword"], \
            "ignore_match_types": ["keyword_any", "keyword_boundary_end"]})
        self.assert_result_not_empty(result, "dummy")
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_any"), \
            0)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_begin"), \
            48)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_end"), \
            0)
        self.assertEqual(self.count_matches(result, "dummy", "file1", "keyword_boundary_all"), \
            40)

    def test_stop_after(self):
        result = self.scan_package(["dummy"], {"methods": ["keyword"], "stop_after": 2})
        self.assert_result_not_empty(result, "dummy")
        self.assertEqual(len(result["dummy"]["report"]), 2)

        result = self.scan_package(["dummy"], {"methods": ["keyword"], "stop_after": 1})
        self.assert_result_not_empty(result, "dummy")
        self.assertEqual(len(result["dummy"]["report"]), 1)

    def test_source_files_only(self):
        result = self.scan_package(["dummy"], {"methods": ["keyword"], "source_files_only": True})
        self.assert_result_not_empty(result, "dummy")
        self.assertEqual(len(result["dummy"]["report"]), 1)

        current_directory = os.path.dirname(os.path.abspath(__file__))
        file_full_path = os.path.join(current_directory, "dummy")
        file_full_path = os.path.join(file_full_path, "file.cpp")

        self.assertTrue(file_full_path in result["dummy"]["report"])

    def test_no_matches(self):
        result = self.scan_package(["dummy3"], {"methods": ["keyword"]})
        self.assertTrue("dummy3" in result)
        self.assertTrue("report" in result["dummy3"])
        self.assertTrue(result["dummy3"]["report"] == {})

    def test_line_text(self):
        for match in self.get_dummy2_matches():
            if match["match_type"] == "keyword_any":
                self.assertEqual(match["line_text"], "testtestloremtesttest")

            elif match["match_type"] == "keyword_boundary_begin":
                self.assertEqual(match["line_text"], "testtest IPSUM test")

            elif match["match_type"] == "keyword_boundary_end":
                self.assertEqual(match["line_text"], "test dolor")

    def test_match_file_index(self):
        for match in self.get_dummy2_matches():
            if match["match_type"] == "keyword_any":
                self.assertEqual(match["match_file_index_begin"], 8)
                self.assertEqual(match["match_file_index_end"], 13)

            elif match["match_type"] == "keyword_boundary_begin":
                self.assertEqual(match["match_file_index_begin"], 41)
                self.assertEqual(match["match_file_index_end"], 46)

            elif match["match_type"] == "keyword_boundary_end":
                self.assertEqual(match["match_file_index_begin"], 67)
                self.assertEqual(match["match_file_index_end"], 72)

    def test_match_line_index(self):
        for match in self.get_dummy2_matches():
            if match["match_type"] == "keyword_any":
                self.assertEqual(match["match_line_index_begin"], 8)
                self.assertEqual(match["match_line_index_end"], 13)

            elif match["match_type"] == "keyword_boundary_begin":
                self.assertEqual(match["match_line_index_begin"], 9)
                self.assertEqual(match["match_line_index_end"], 14)

            elif match["match_type"] == "keyword_boundary_end":
                self.assertEqual(match["match_line_index_begin"], 5)
                self.assertEqual(match["match_line_index_end"], 10)

    def test_line_number(self):
        for match in self.get_dummy2_matches():
            if match["match_type"] == "keyword_any":
                self.assertEqual(match["match_line_number"], 1)

            elif match["match_type"] == "keyword_boundary_begin":
                self.assertEqual(match["match_line_number"], 4)

            elif match["match_type"] == "keyword_boundary_end":
                self.assertEqual(match["match_line_number"], 7)

    def test_match_text(self):
        for match in self.get_dummy2_matches():
            if match["match_type"] == "keyword_any":
                self.assertEqual(match["match_text"], "lorem")

            elif match["match_type"] == "keyword_boundary_begin":
                self.assertEqual(match["match_text"], "IPSUM")

            elif match["match_type"] == "keyword_boundary_end":
                self.assertEqual(match["match_text"], "dolor")
