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
from configparser import ConfigParser
from cryptodetector import Languages
from cryptodetector.exceptions import InvalidKeywordList, InvalidRegexException

class Regex(object):
    """Class for searching file contents for a set of regular expressions defined in a config file
    """
    def __init__(self, ignore_case=False, ignore_match_types=[]):
        self.group_names = {}
        self.regex = {}
        self.automaton = {}
        self.flags = 0
        if ignore_case:
            self.flags = re.IGNORECASE
        self.ignore_match_types = ignore_match_types

    def compile_pattern_list(self, keyword_list_path):
        """Compiles list of regular expressions defined in a config file (eg keyword list)

        Returns:
            None

        Raises:
            InvalidKeywordList
        """

        # load config file
        config = ConfigParser(allow_no_value=True, delimiters=('='))
        config.optionxform = str
        config.read(keyword_list_path)
        keywords = {}
        for section in config.sections():
            keywords[section] = []
            for item, _ in config.items(section):
                keywords[section].append(item)

        languages = Languages.get_list()
        for language in languages:
            self.regex[language] = ""
            self.group_names[language] = []
            self.automaton[language] = None

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

            non_capturing_group = ""

            for pattern in keywords[match_spec_string]:
                if pattern[0] != "\"" or pattern[-1] != "\"" or len(pattern) < 2:
                    raise InvalidRegexException("In file " + keyword_list_path \
                        + ", and in section " \
                        + "[" + match_spec_string \
                        + "]\n\nInvalid regular expression pattern:\n" \
                        + pattern + "\n\nPatterns should begin and end with a quote.")

                # removing quotes around the regex pattern
                pattern = pattern[1:-1]

                # replace end-of-token symbol
                pattern.replace("\\b", r"\b")

                non_capturing_group += "(?:" + pattern + ")|"

            self.regex[match_language] += "(" + non_capturing_group[:-1] + ")|"
            self.group_names[match_language].append(match_spec)

            # apply 'source' and 'all' patterns to all languages
            if match_language in ["source", "all"]:
                for language in languages:
                    if language not in ["source", "all"]:
                        self.regex[language] += "(" + non_capturing_group[:-1] + ")|"
                        self.group_names[language].append(match_spec)

        # compile
        for language in languages:
            if self.regex[language]:
                try:
                    self.automaton[language] = re.compile(self.regex[language][:-1], \
                        flags=self.flags)
                except re.error as expn:
                    raise InvalidRegexException("Failed to compile regular expression\n'" \
                        + self.regex[language][:-1] + "'\n\n" + str(expn))

    def search(self, content, language):
        """Search file content and find all matches

        Args:
            content: (string) file content
            language: (string) see langauges.py

        Returns:
            (list) of dict objects for each match, containing all the output fields
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

        def get_match_spec(match):
            """Lookup match specifications from the match object

            Args:
                match: (_sre.SRE_Match)

            Returns:
                (string) match type
            """
            group_index = 0

            for group in match.groups():
                if group:
                    return self.group_names[language][group_index]
                group_index += 1

        if self.automaton[language] is None:
            return []

        matches = self.automaton[language].finditer(content)

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
            match_spec = get_match_spec(match)
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
        if self.automaton[language] is None:
            return False

        return self.automaton[language].search(content) != None
