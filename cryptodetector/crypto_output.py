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

import copy
import hashlib
import codecs

from cryptodetector import Language

class CryptoOutput(object):
    """Class for structuring the JSON data in the crypto output"""

    # the version of the crypto specification with which this output format complies
    CRYPTO_SPEC_VERSION = 3.0


    def __init__(self):
        self.__JSON_data = {

            "file_collection_verification_code": None,

            "crypto_spec_version": CryptoOutput.CRYPTO_SPEC_VERSION,

            "package_name": None,

            "crypto_evidence": {}
        }

    @staticmethod
    def required_output_fields():
        """defines the output fields and what is required by a match object.

        If a field is required (has a true next to it) and is missing, the program will throw an
        error and exit.

        The ones that are not required (have a false value) are _expected_, but if not present, they
        will be added as blank.

        Every match will have at least these fields.

        Args:
            None

        Returns:
            (dict) key-value pair of field to a boolean indicating wether it is required.
        """
        return {
            "comments": False,
            "human_reviewed": False,
            "line_text": False,
            "line_text_after_1": False,
            "line_text_after_2": False,
            "line_text_after_3": False,
            "line_text_before_1": False,
            "line_text_before_2": False,
            "line_text_before_3": False,
            "file_index_begin": True,
            "file_index_end": True,
            "line_index_begin": False,
            "line_index_end": False,
            "line_number": False,
            "matched_text": True,
            "evidence_type": True,
            "detection_method": True,
            "encryption_api_usage": False,
            "encryption_library": False
        }

    def set_package_name(self, package_name):
        """Set the package name

        Args:
            package_name: (string)

        Returns:
            None
        """
        self.__JSON_data["package_name"] = package_name


    def set_verif_code(self, sha1_list):
        """Computes the file collection verification code as a means of uniquely identifying a set
        of files. To this end, first sort the list of file SHA1's in ascending order, concatenate
        this list to a single string, and take SHA1 of the resulting string.

        Args:
            sha1_list: (list) of file SHA1's at the leaves of package file tree

        Returns
            None
        """

        joined_sha1s = "".join(sorted(sha1_list))
        verif_code = hashlib.sha1(codecs.encode(joined_sha1s, "utf-8")).hexdigest()
        self.__JSON_data["file_collection_verification_code"] = verif_code

    def add_hit(self, file_path, file_sha1, file_language, hit):
        """Adds a hit in the file with the given SHA1 and path

        Args:
            file_path: (string)
            file_sha1: (string)
            hit: (dict)

        Returns
            None
        """
        if file_sha1 not in self.__JSON_data["crypto_evidence"]:
            self.__JSON_data["crypto_evidence"][file_sha1] = {
                "file_paths": [],
                "hits": [],
                "is_source_code": file_language.is_source_code
                }

        if file_path not in self.__JSON_data["crypto_evidence"][file_sha1]["file_paths"]:
            self.__JSON_data["crypto_evidence"][file_sha1]["file_paths"].append(file_path)

            if self.__JSON_data["crypto_evidence"][file_sha1]["is_source_code"] != \
                file_language.is_source_code:
                self.__JSON_data["crypto_evidence"][file_sha1]["is_source_code"] = True

        self.__JSON_data["crypto_evidence"][file_sha1]["hits"].append(copy.copy(hit))

    def get_crypto_data(self):
        """Return the JSON data

        Args:
            None

        Returns:
            (string) JSON formatted data
        """
        return self.__JSON_data
