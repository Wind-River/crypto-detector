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

import re
import bisect
import json
import configparser
from cryptodetector import Languages
from cryptodetector.exceptions import InvalidKeywordList

class Regex(object):
    """Class for searching file contents for a set of regular expressions defined in a config file
    """
    def __init__(self, ignore_case=False, ignore_match_types=[], whole_words=False):
        self.keywords = {}
        self.match_specs = {}
        self.flags = 0
        self.ignore_case = ignore_case
        self.whole_words = whole_words
        if ignore_case:
            self.flags = re.IGNORECASE
        self.ignore_match_types = ignore_match_types

    def read_keyword_list(self, keyword_list_path):
        """reads the set of keywords defined in a config file

        Args:
            keyword_list_path: (string) path to the keyword list config file

        Returns:
            None

        Raises:
            InvalidKeywordList
        """

        # read config file
        config = configparser.ConfigParser(allow_no_value=True, delimiters=('='))
        config.optionxform = str
        try:
            config.read(keyword_list_path)
        except (configparser.Error, AttributeError) as error:
            raise InvalidKeywordList("Failed to parse keyword list " + keyword_list_path \
                + ":\n" + str(error))
        keywords = {}
        for section in config.sections():
            keywords[section] = []
            for item, _ in config.items(section):
                keywords[section].append(item)

        languages = Languages.get_list()
        for language in languages:
            self.keywords[language] = {}

        # parse keywords
        for match_spec_string in keywords:
            try:
                match_spec = json.loads(match_spec_string)
            except json.JSONDecodeError as decode_error:
                raise InvalidKeywordList("In file " + keyword_list_path \
                    + ", and in section " \
                    + "[" + match_spec_string + "]\n\n Invalid JSON string: '" \
                    + match_spec_string + "'\n"+ str(decode_error))
            if "match_type" not in match_spec:
                raise InvalidKeywordList("In file " + keyword_list_path \
                    + ", and in section " \
                    + "[" + match_spec_string + "]\n\n, Missing key 'match_type'.")

            match_type = match_spec["match_type"]
            if "language" in match_spec:
                match_language = match_spec["language"]
            else:
                match_language = "all"

            if match_language not in languages:
                raise InvalidKeywordList("In file " + keyword_list_path \
                    + ", and in section " \
                    + "[" + match_spec_string + "]\n\nInvalid language: '" + match_language \
                    + "'. It must be one of " + str(languages))

            if match_type in self.ignore_match_types:
                continue

            if not keywords[match_spec_string]:
                continue

            for keyword in keywords[match_spec_string]:
                if keyword[0] != "\"" or keyword[-1] != "\"" or len(keyword) < 2:
                    raise InvalidKeywordList("In file " + keyword_list_path \
                        + ", and in section " \
                        + "[" + match_spec_string \
                        + "]\n\nInvalid keyword:\n" \
                        + keyword + "\n\nKeywords should begin and end with a quote.")

                # removing quotes around the keyword
                keyword = keyword[1:-1]

                if self.ignore_case:
                    keyword = keyword.lower()

                # removing \b character
                keyword_no_boundary = keyword.replace("\\b", "")

                # escape special characters
                keyword_re_escaped = re.escape(keyword).replace("\\\\b", r"\b")

                if self.whole_words:
                    keyword_re_escaped = r"\b" + keyword_re_escaped + r"\b"

                self.keywords[match_language][keyword_no_boundary] = keyword_re_escaped

                # use keyword in lower-case as a unique identifier to lookup match type from
                # match text
                keyword_identifier = keyword_no_boundary.lower()
                if keyword_identifier in self.match_specs:
                    raise InvalidKeywordList("In file " + keyword_list_path \
                        + ", and in section " \
                        + "[" + match_spec_string \
                        + "]\n\nDuplicate keyword: '" + keyword_identifier + "'.")
                self.match_specs[keyword_identifier] = match_spec

                # apply 'source' and 'all' to all other languages
                if match_language in ["source", "all"]:
                    for language in languages:
                        if language not in ["source", "all"]:
                            self.keywords[language][keyword_no_boundary] = keyword_re_escaped

    def search(self, content, language):
        """Search file content and find all the matches

        Args:
            content: (string) file content
            language: (string) file language; see langauges.py

        Returns:
            (list) of matches, where a match is a dict object containing all the output fields
        """
        def line_text_surrounding(line_number, lines):
            """Returns the line text at the line_number

            Args:
                line_number: (integer)
                lines: (list) lines of text

            Returns:
                (string)
            """
            try:
                return lines[line_number]
            except IndexError:
                return ""

        # quick first pass to detect if any keyword exists
        found = []
        if self.ignore_case:
            content_lower = content.lower()
            for keyword in self.keywords[language]:
                if keyword in content_lower:
                    found.append(keyword)
        else:
            for keyword in self.keywords[language]:
                if keyword in content:
                    found.append(keyword)

        if not found:
            return []

        # make a regular expression of found items and find their exact location
        found_regex = ""
        for found_keyword in found:
            found_regex += "(?:" + self.keywords[language][found_keyword] + ")|"

        matches = re.finditer(found_regex[:-1], content, flags=self.flags)

        if not matches:
            return []

        result = []
        lines = content.split("\n")
        line_break_indicies = [0]
        index = 0

        for line in lines:
            index += len(line)
            line_break_indicies.append(index)
            index += 1

        for match in matches:
            match_text = content[match.start(): match.end()]
            match_spec = self.match_specs[match_text.lower()]
            line_number = bisect.bisect_left(line_break_indicies, match.start()) - 1
            match_line_index_begin = match.start() - line_break_indicies[line_number]
            if line_number > 1:
                match_line_index_begin -= 1
            match_line_index_end = match_line_index_begin + (match.end() - match.start())
            line_text = lines[line_number]

            match = {"match_text": match_text,
                     "line_text": line_text,
                     "match_line_number": line_number + 1,
                     "match_file_index_begin": match.start(),
                     "match_file_index_end": match.end(),
                     "match_line_index_begin": match_line_index_begin,
                     "match_line_index_end": match_line_index_end,
                     "line_text_before_1": line_text_surrounding(line_number - 1, lines),
                     "line_text_before_2": line_text_surrounding(line_number - 2, lines),
                     "line_text_before_3": line_text_surrounding(line_number - 3, lines),
                     "line_text_after_1": line_text_surrounding(line_number + 1, lines),
                     "line_text_after_2": line_text_surrounding(line_number + 2, lines),
                     "line_text_after_3": line_text_surrounding(line_number + 3, lines),
                     "human_reviewed": "",
                     "comments": ""
                    }

            for key in match_spec:
                if key != "language":
                    match[key] = match_spec[key]

            result.append(match)

        return result

    def quick_search(self, content, language):
        """Quickly search content for one or more matches

        Args:
            content: (string) file content
            language: (string) see langauges.py

        Returns:
            (bool) True if it found any matches in content, False otherwise
        """
        for keyword in self.keywords[language]:
            if keyword in content:
                # search again with re to account for boundary (\b) character
                if re.search(self.keywords[language][keyword], content, flags=self.flags) != None:
                    return True
        return False