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

from os.path import dirname, realpath, join
from cryptodetector import Method, Regex, Languages

class APIFinder(Method):
    """Class for searching for API usage
    """
    method_id = "api"

    def __init__(self):
        self.regex = Regex(ignore_match_types=Method.ignore_match_types, whole_words=True)
        self.regex.read_keyword_list(join(dirname(realpath(__file__)), "api_patterns.txt"))

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
