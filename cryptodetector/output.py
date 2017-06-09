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

import sys
import os
import codecs
from cryptodetector import Logger

class Output():
    """Organization of the output of the program
    """
    ANSI_WARNING = '\033[93m'
    ANSI_FAIL = '\033[91m'
    ANSI_BOLD = '\033[1m'
    ANSI_UNDERLINE = '\033[4m'
    ANSI_END = '\033[0m'

    verbose = False
    suppress_warnings = False

    @staticmethod
    def print_string(string):
        """Explicitly encode the string, replacing non-unicode characters
        and write to standard output bufffer
        """
        sys.stdout.buffer.write(codecs.encode(string + str("\n"), "utf-8", "replace"))

    @staticmethod
    def print_output(output):
        """Print output data

        Args:
            output: (string)

        Returns:
            None
        """
        Output.print_string("\n\n")
        Output.print_string(output)

    @staticmethod
    def print_information(text, ignore_verbose=False):
        """Print standard text information

        Args:
            text: (string)
            ignore_verbose: (bool)

        Returns:
            None
        """
        if ignore_verbose or Output.verbose:
            Output.print_string(text)

    @staticmethod
    def print_error(message):
        """Print an error to standard error

        Args:
            message: (string)

        Returns:
            None
        """
        if os.name == "nt":
            sys.stderr.write("\nERROR: " + message + "\n\n")
        else:
            sys.stderr.write("\n" + Output.ANSI_FAIL + "ERROR: " + message + Output.ANSI_END \
                + "\n\n")
        Logger.log_error(message)

    @staticmethod
    def print_warning(message):
        """Print a warning to standard error

        Args:
            message: (string)

        Returns:
            None
        """
        if not Output.suppress_warnings:
            if os.name == "nt":
                sys.stderr.write("\nWARNING: " + message + "\n\n")
            else:
                sys.stderr.write("\n" + Output.ANSI_WARNING + "WARNING: " + message \
                    + Output.ANSI_END + "\n\n")
