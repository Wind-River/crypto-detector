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

import os
import datetime

class Logger(object):
    """Class for saving log information and creating a log file
    """
    events = ""
    errors = ""

    @staticmethod
    def log(message):
        """Log information

        Args:
            message: (string)

        Returns:
            None
        """
        Logger.events += "[" + str(datetime.datetime.now()) + "] " + message + "\n"

    @staticmethod
    def log_error(message):
        """Log error message

        Args:
            message: (string)

        Returns:
            None
        """
        Logger.errors += "[" + str(datetime.datetime.now()) + "] ERROR: " + message + "\n"

    def write_log_files(output_directory):
        """Write event log and error log files

        Args:
            output_directory: (string)

        Returns:
            None
        """
        datetime_string = datetime.datetime.now().strftime("%m-%d-%Y.%I-%m-%p")
        stamp = datetime_string + "." + str(os.getpid())
        log_filename = os.path.join(output_directory, "crypto.events." + stamp + ".log")
        error_log_filename = os.path.join(output_directory, "crypto.errors." + stamp + ".log")

        if Logger.events:
            with open(log_filename, "w") as log_file:
                log_file.write(Logger.events)
                if Logger.errors:
                    log_file.write("\n\nEncountered the following errors:\n\n")
                    log_file.write(Logger.errors)
