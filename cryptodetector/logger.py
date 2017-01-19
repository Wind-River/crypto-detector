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

    @staticmethod
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
            with open(log_filename, "a") as log_file:
                log_file.write("\n\nEncountered the following errors:\n\n")
                log_file.write(Logger.errors)
