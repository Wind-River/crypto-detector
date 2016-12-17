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

class Languages(object):
    """Defines set of supported languages
    """
    Unknown = -3
    Unsupported = -2
    Binary = -1
    Plain_text = "all"
    Source_code = "source"
    C = "c"
    Python = "python"
    Java = "java"
    Shell = "shell"
    Perl = "perl"
    Javascript = "javascript"
    Scala = "scala"
    MSDOS = "msdos"
    Haskell = "haskell"
    Pascal = "pascal"

    @staticmethod
    def get_list():
        """List all languages

        Args:
            None

        Returns:
            (list)
        """
        return ["all", "source", "c", "python", "java", "shell", "perl", "javascript", \
            "scala", "haskell", "pascal"]

    @staticmethod
    def is_text(language):
        """Determine if the given language is text

        Args:
            language: (string)

        Returns:
            (bool) whether language is text-based.
        """
        return language in Languages.get_list()

    @staticmethod
    def is_source_code(language):
        """Determine if the given language is source code

        Args:
            language: (string)

        Returns:
            (bool) whether given langauge is a source code language
        """
        return language in ["c", "python", "java", "shell", "perl", \
            "javascript", "scala", "haskell", "pascal"]
