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

from abc import ABCMeta

class LanguageType(ABCMeta):
    def __repr__(cls):
        return cls.string_repr

    def __eq__(cls, other):
        return cls.string_repr == other.string_repr

    def __ne__(cls, other):
        return cls.string_repr != other.string_repr


class Language(object):
    """Defines set of supported file languages and their respective file extensions
    """
    class Unknown(metaclass=LanguageType):
        string_repr = "unknown"
        is_text = False
        is_binary = False
        is_source_code = False
        extensions = []

    class Binary(metaclass=LanguageType):
        string_repr = "binary"
        is_text = False
        is_binary = True
        is_source_code = False
        extensions = []

    class PlainText(metaclass=LanguageType):
        string_repr = "all"
        is_text = True
        is_binary = False
        is_source_code = False
        extensions = ["txt", "text", "xml", "html", "xsl", "xspf"]

    class C(metaclass=LanguageType):
        string_repr = "c"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["c", "cc", "cp", "cpp", "c++", "cxx", "h", "hh", "hxx", "hpp", "h++", "moc"]

    class Python(metaclass=LanguageType):
        string_repr = "python"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["py", "rpy", "pyt", "pyw", "pym", "re"]

    class Java(metaclass=LanguageType):
        string_repr = "java"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["java", "jsp", "j"]

    class Shell(metaclass=LanguageType):
        string_repr = "shell"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["sh", "csh", "ksh", "run", "bsh", "bash"]

    class Perl(metaclass=LanguageType):
        string_repr = "perl"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["pl"]

    class Javascript(metaclass=LanguageType):
        string_repr = "javascript"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["js", "javascript", "json"]

    class Scala(metaclass=LanguageType):
        string_repr = "scala"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["scala"]

    class MSDOS(metaclass=LanguageType):
        string_repr = "msdos"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["bat"]

    class Haskell(metaclass=LanguageType):
        string_repr = "haskell"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["hs", "lhs"]

    class PHP(metaclass=LanguageType):
        string_repr = "php"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["php"]

    class Patch(metaclass=LanguageType):
        string_repr = "patch"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["patch"]

    class Pascal(metaclass=LanguageType):
        string_repr = "pascal"
        is_text = True
        is_binary = False
        is_source_code = True
        extensions = ["p"]

    @staticmethod
    def language_list():
        return [getattr(Language, attr) for attr in Language.__dict__.keys() \
            if type(getattr(Language, attr)) == LanguageType]

    @staticmethod
    def text_languages():
        return [str(lang) for lang in Language.language_list() if lang.is_text]

    @staticmethod
    def guess_language(file_extension):
        for lang in Language.language_list():
            if file_extension in lang.extensions:
                return lang
        return Language.Unknown
