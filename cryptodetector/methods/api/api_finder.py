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

from os.path import dirname, realpath, join
from cryptodetector import Method, Regex, Languages

class APIFinder(Method):
    """Class for searching for API usage
    """
    method_id = "api"
    kwlist_version = None

    options= {
        "kwlist_path": join(dirname(realpath(__file__)), "api_definitions.txt")
    }

    options_help = {
        "kwlist_path": "Path to the file containing list of API definitions"
    }

    def __init__(self):
        self.regex = Regex(ignore_match_types=Method.ignore_match_types, whole_words=True)
        self.regex.read_keyword_list(APIFinder.options["kwlist_path"])
        APIFinder.options["keyword_list_version"] = self.regex.kwlist_version()

    def supports_scanning_file(self, language):
        """This method supports scanning all text files

        Args:
            language: (string) see langauges.py

        Returns:
            (bool)
        """
        return Languages.is_text(language)

    def search(self, content, language):
        """Search file content and find all matches

        Args:
            content: (string) file content
            language: (string) see langauges.py

        Returns:
            (list) of dict objects containing the output fields
        """
        return self.regex.search(content, language)

    def quick_search(self, content, language):
        """Quickly search content for one or more matches

        Args:
            content: (string) file content
            language: (string) see langauges.py

        Returns:
            (bool) True if it found any matches in content, False otherwise
        """
        return self.regex.quick_search(content, language)
