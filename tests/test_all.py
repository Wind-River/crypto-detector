"""
/* <legal-notice>
*
* Copyright (c) 2016 Wind River Systems, Inc.
*
* This software has been developed and maintained under the Wind River
* CodeSwap program. The right to copy, distribute, modify, or otherwise
* make use of this software may be licensed only pursuant to the terms
* of an applicable Wind River license agreement.
*
* <credits>
*   { Kamyar Kaviani,  kamyar.kaviani@windriver.com}
* </credits>
*
* </legal-notice>
*/
"""

import os
from unittest import TestCase
from cryptodetector import Options, CryptoDetector, MethodFactory

class TestCryptoId(TestCase):
    """Unit Tests
    """

    PACKAGE_HOST = "https://distro.windriver.com/sources/wrlinux-8/"

    def default_input(self, package):
        options = Options()._get_options()
        options["skip_output"] = True
        options["verbose"] = False
        options["packages"] = [package]
        options["suppress_warnings"] = True
        return options

    def count_field(self, data, field, value):
        return len([match for match in data if match[field] == value])

    def file_count(self, data):
        return len(set([match["file_path"] for match in data]))

    def get_result(self, method, package, options={}, name=None, ignore_case=False):

        inputs = self.default_input(package)
        inputs["methods"] = [method]

        for option in options:
            inputs[option] = options[option]

        package_name = package.split("/")[-1]
        if name:
            package_name = name

        self.methods()[method].options["ignore_case"] = ignore_case
        result = CryptoDetector(inputs, skip_output=True).scan()

        return result[package_name]

    def methods(self):
        return {mc.method_id: mc for mc in MethodFactory.method_classes}

    def test_keyword_dummy_case_sensitive(self):
        current_directory = os.path.dirname(os.path.realpath(__file__))
        package = current_directory + "/test_packages/dummy"
        result = self.get_result("keyword", package)
        generic_count = self.count_field(result, "match_type", "generic")
        des_count = self.count_field(result, "match_type", "algorithm/symmetric/block-cipher/DES")

        self.assertGreater(generic_count, 0)
        self.assertGreater(des_count, 0)


    def test_keyword_case_ignore_case(self):
        current_directory = os.path.dirname(os.path.realpath(__file__))
        package = current_directory + "/test_packages/dummy"
        result = self.get_result("keyword", package, ignore_case=True)
        des_count = self.count_field(result, "match_type", "algorithm/symmetric/block-cipher/DES")

        self.assertGreater(des_count, 0)


