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
