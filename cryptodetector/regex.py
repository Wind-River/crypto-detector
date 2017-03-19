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
import json
import os
import configparser
from cryptodetector import Languages
from cryptodetector.exceptions import InvalidKeywordList

class Regex(object):
    """Class for searching file contents for keywords using regular expressions
    """
    def __init__(self, ignore_case=False, ignore_evidence_types=[], whole_words=False):
        self.keywords = {}
        self.match_specs = {}
        self.flags = 0
        self.ignore_case = ignore_case
        self.whole_words = whole_words
        if ignore_case:
            self.flags = re.IGNORECASE
        self.ignore_evidence_types = ignore_evidence_types
        self.keyword_list_version = None

    def read_keyword_list(self, keyword_list_path):
        """reads the set of keywords defined in a config file

        Args:
            keyword_list_path: (string) path to the keyword list config file

        Returns:
            None

        Raises:
            InvalidKeywordList
        """
        if not os.path.isfile(keyword_list_path):
            raise InvalidKeywordList("Keyword list file '" + keyword_list_path + "' did not exist.")

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

        if not config.has_section("keyword_list_version"):
            raise InvalidKeywordList("Keyword list file " + keyword_list_path \
                + " is invalid. Missing required section 'keyword_list_version'")
        if len(config.items("keyword_list_version")) != 1:
               raise InvalidKeywordList("Keyword list file " + keyword_list_path \
                + " is invalid. There should be one value in 'keyword_list_version' section.")
        self.keyword_list_version = config.items("keyword_list_version")[0][0]

        languages = Languages.get_list()
        for language in languages:
            self.keywords[language] = []

        # parse keywords
        for match_spec_string in keywords:
            if match_spec_string == "keyword_list_version":
                continue
            try:
                match_spec = json.loads(match_spec_string)
            except json.JSONDecodeError as decode_error:
                raise InvalidKeywordList("In file " + keyword_list_path \
                    + ", and in section " \
                    + "[" + match_spec_string + "]\n\n Invalid JSON string: '" \
                    + match_spec_string + "'\n"+ str(decode_error))
            if "evidence_type" not in match_spec:
                raise InvalidKeywordList("In file " + keyword_list_path \
                    + ", and in section " \
                    + "[" + match_spec_string + "]\n\n, Missing key 'evidence_type'.")

            evidence_type = match_spec["evidence_type"]
            if "language" in match_spec:
                match_language = match_spec["language"]
            else:
                match_language = "all"

            if match_language not in languages:
                raise InvalidKeywordList("In file " + keyword_list_path \
                    + ", and in section " \
                    + "[" + match_spec_string + "]\n\nInvalid language: '" + match_language \
                    + "'. It must be one of " + str(languages))

            if evidence_type in self.ignore_evidence_types:
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

                self.keywords[match_language].append((keyword_no_boundary, keyword_re_escaped))

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
                            self.keywords[language].append( \
                                (keyword_no_boundary, keyword_re_escaped))

        # Sort keywords by length and alphabetically to make search behaviour well defined
        # when there exists keywords that are prefixes of one another (eg crypt and cryptEncrypt)
        for language in languages:
            self.keywords[language] = sorted(self.keywords[language], \
                key=lambda t: (len(t[0]), str.lower(t[0])), reverse=True)

    def kwlist_version(self):
        """Get keyword list version

        Args:
            None

        Returns:
            (integer) keyword list version number
        """
        return self.keyword_list_version

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
            if line_number < 0 or line_number >= len(lines):
                return ""
            return lines[line_number]

        # quick first pass to detect if any keyword exists
        found = []
        if self.ignore_case:
            content_lower = content.lower()
            for keyword, keyword_re in self.keywords[language]:
                if keyword in content_lower:
                    found.append(keyword_re)
        else:
            for keyword, keyword_re in self.keywords[language]:
                if keyword in content:
                    found.append(keyword_re)

        if not found:
            return []

        # make a regular expression of found items to find all their occurances
        found_regex = ""
        for found_keyword in found:
            found_regex += "(?:" + found_keyword + ")|"

        # search line by line
        result = []
        line_number = 0
        chars_searched = 0
        lines = content.split("\n")
        for line in lines:
            for match in re.finditer(found_regex[:-1], line, flags=self.flags):
                match_dict = {
                    "matched_text": line[match.start(): match.end()],
                    "line_text": line,
                    "line_number": line_number + 1,
                    "file_index_begin": chars_searched + match.start(),
                    "file_index_end": chars_searched + match.end(),
                    "line_index_begin": match.start(),
                    "line_index_end": match.end(),
                    "line_text_before_1": line_text_surrounding(line_number - 1, lines),
                    "line_text_before_2": line_text_surrounding(line_number - 2, lines),
                    "line_text_before_3": line_text_surrounding(line_number - 3, lines),
                    "line_text_after_1": line_text_surrounding(line_number + 1, lines),
                    "line_text_after_2": line_text_surrounding(line_number + 2, lines),
                    "line_text_after_3": line_text_surrounding(line_number + 3, lines)
                    }

                match_spec = self.match_specs[match_dict["matched_text"].lower()]
                for key in match_spec:
                    if key != "language":
                        match_dict[key] = match_spec[key]

                result.append(match_dict)

            chars_searched += len(line) + 1
            line_number += 1

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
