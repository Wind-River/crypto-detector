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

import re
from cryptodetector import Method, Languages

class HelloWorldScanner(Method):
    """Hello, World template method
    """

    method_id = "hello_world"

    # options={
    #     "example_value": 123,
    #     "example_array": [],
    #     "example_boolean": False
    # }

    # These help messages will be printed when the user brings up the help guide with -h

    # options_help = {
    #     "example_value": "This is an example help message describing example_value",
    #     "example_array": "This is an example help message describing example_array",
    #     "example_boolean": "This is an example help message describing example_boolean"
    # }

    def supports_scanning_file(self, language):
        """This method supports scanning all text files

        Args:
            language: (string) see langauges.py

        Returns:
            (bool) whether it supports scanning a file in the given language
        """
        return Languages.is_text(language)

    def quick_search(self, content, language):
        """Quickly search the content for the string "Hello, World"

        Args:
            content: (string) the file content in which to search
            language: (string) see langauges.py

        Returns:
            (bool) whether it found a match anywhere in the content
        """
        return "Hello, World" in content

    def search(self, content, language):
        """Search all occurances of the string "Hello, World"

        Args:
            content: (string) the file content in which to search
            language: (string) see langauges.py

        Returns:
            (list) list of matches. A match is a dict object containing the output fields
        """
        result = []

        for match in re.finditer("Hello, World", content):

            result.append({"evidence_type": "generic", \
                           "matched_text": "Hello, World", \
                           "file_index_begin": match.start(), \
                           "file_index_end": match.end()})

        return result
