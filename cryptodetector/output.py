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

import sys
import os
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
    def print_output(output):
        """Print output data

        Args:
            output: (string)

        Returns:
            None
        """
        print("\n\n")
        print(output)

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
            print(text)

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
