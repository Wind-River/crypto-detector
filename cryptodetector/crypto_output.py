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

import copy

class CryptoOutput(object):
    """Class for structuring the JSON data in the crypto output"""


    # !!IMPORTANT: update this version whenever a change is made to this output format
    CRYPTO_SPEC_VERSION = 1.0


    def __init__(self):
        self.__JSON_data = {
            "crypto_output_spec_version": CryptoOutput.CRYPTO_SPEC_VERSION,

            "crypto_detector_version": None,

            "package_name": None,

            "stats": {
                "bytes_of_binary_processed": None,
                "bytes_of_text_processed": None,
                "execution_time": None,
                "file_count": None,
                "lines_of_text_processed": None
            },

            "scan_settings": {
                "ignore_match_types": None,
                "log": None,
                "output_existing": None,
                "quick": None,
                "source_files_only": None,
                "stop_after": None,
                "methods": {
                    "api": {
                        "active": None,
                        "keyword_list_version": None
                    },
                    "keyword": {
                        "active": None,
                        "ignore_case": None,
                        "keyword_list_version": None
                    }
                }
            },

            "errors": [],

            "report": {}
        }

    def required_output_fields(self):
        """defines what to expect in each match"""
        return [
            "comments",
            "human_reviewed",
            "line_text",
            "line_text_after_1",
            "line_text_after_2",
            "line_text_after_3",
            "line_text_before_1",
            "line_text_before_2",
            "line_text_before_3",
            "match_file_index_begin",
            "match_file_index_end",
            "match_line_index_begin",
            "match_line_index_end",
            "match_line_number",
            "match_text",
            "match_type",
            "method"
        ]

    def set_crypto_detector_version(self, version):
        """Sets the version of the script"""
        self.__JSON_data["crypto_detector_version"] = version

    def set_package_name(self, package_name):
        """Set the package name"""
        self.__JSON_data["package_name"] = package_name

    def set_scan_settings(self,
                          ignore_match_types,
                          log,
                          output_existing,
                          quick,
                          source_files_only,
                          stop_after,
                          method_api_active,
                          method_api_kwlist_version,
                          method_keyword_active,
                          method_keyword_ignore_case,
                          method_keyword_kwlist_version):
        """Set the scan settings"""
        self.__JSON_data["scan_settings"]["ignore_match_types"] = ignore_match_types
        self.__JSON_data["scan_settings"]["log"] = log
        self.__JSON_data["scan_settings"]["output_existing"] = output_existing
        self.__JSON_data["scan_settings"]["quick"] = quick
        self.__JSON_data["scan_settings"]["source_files_only"] = source_files_only
        self.__JSON_data["scan_settings"]["stop_after"] = stop_after
        self.__JSON_data["scan_settings"]["methods"]["api"]["active"] = method_api_active
        self.__JSON_data["scan_settings"]["methods"]["api"]["keyword_list_version"] \
            = method_api_kwlist_version
        self.__JSON_data["scan_settings"]["methods"]["keyword"]["active"] \
            = method_keyword_active
        self.__JSON_data["scan_settings"]["methods"]["keyword"]["ignore_case"] \
            = method_keyword_ignore_case
        self.__JSON_data["scan_settings"]["methods"]["keyword"]["keyword_list_version"] \
            = method_keyword_kwlist_version

    def set_stats(self,
                  bytes_of_binary_processed,
                  bytes_of_text_processed,
                  execution_time,
                  file_count,
                  lines_of_text_processed):
        """Sets scan statistics"""
        self.__JSON_data["stats"]["bytes_of_binary_processed"] = bytes_of_binary_processed
        self.__JSON_data["stats"]["bytes_of_text_processed"] = bytes_of_text_processed
        self.__JSON_data["stats"]["execution_time"] = execution_time
        self.__JSON_data["stats"]["file_count"] = file_count
        self.__JSON_data["stats"]["lines_of_text_processed"] = lines_of_text_processed

    def add_error(self, error_message):
        """Adds an error message to the errors section"""
        self.__JSON_data["errors"].append(error_message)

    def add_match(self,
                  file_path,
                  file_checksum,
                  match_dict):
        """Adds a match to the report for a given file"""
        if file_path not in self.__JSON_data["report"]:
            self.__JSON_data["report"][file_path] = {}
            self.__JSON_data["report"][file_path]["SHA1_checksum"] = file_checksum
            self.__JSON_data["report"][file_path]["matches"] = []
        else:
            self.__JSON_data["report"][file_path]["matches"].append(copy.copy(match_dict))

    def reset_data(self):
        """Clears out the report data"""
        self.__JSON_data["report"] = {}
        self.__JSON_data["errors"] = []

    def get_crypto_data(self):
        """Returns the JSON data"""
        return self.__JSON_data
