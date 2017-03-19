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

from abc import ABCMeta, abstractmethod
from cryptodetector.exceptions import InvalidMethodException

class MethodFactory(ABCMeta):
    """Meta class creating a method class. Keeps track of all child classes that inherit from Method
    for later reference.
    """
    def __new__(mcs, clsname, bases, dct):

        if not hasattr(MethodFactory, "method_classes"):
            MethodFactory.method_classes = []

        method_class = super(MethodFactory, mcs).__new__(mcs, clsname, bases, dct)

        if bases:
            if not hasattr(method_class, "method_id"):
                raise InvalidMethodException("Method " + clsname + " requires " \
                    + "'method_id' attribute.")

            if method_class.method_id in [mc.method_id for mc in MethodFactory.method_classes]:
                raise InvalidMethodException("Method " + clsname + " has duplicate method_id '" \
                    + method_class.method_id \
                    + "'. method_id must be unique across all available methods.")

            MethodFactory.method_classes.append(method_class)

        return method_class

class Method(metaclass=MethodFactory):
    """Abstract base class providing the interface for a method
    """

    # list of evidence types of all methods should ignore
    ignore_evidence_types = []

    @abstractmethod
    def supports_scanning_file(self, language):
        """Indicates whether this method supports scanning a
        file in the given language

        Args:
            language: (string) see langauges.py

        Returns:
            (bool) whether it supports scanning a file in the given language
        """
        pass

    @abstractmethod
    def search(self, content, language):
        """Search and find all matches in the content

        Args:
            content: the content to be scanned. Its type could be a string for text files or a raw
                byte sequence for binary files.
            language: (string) see langauges.py the language of the content

        Returns:
            (list) list of matches. A match is a dict object containing all the output fields.
        """
        pass

    @abstractmethod
    def quick_search(self, content, language):
        """Quick search the content in the given language

        Args:
            content: the content to be scanned. Its type could be a string for text files or a raw
                byte sequence for binary files.
            language: (string) see langauges.py the language of the content

        Returns:
            (bool) whether it found any matches in the content
        """
        pass
