#!/usr/bin/python3

"""
Copyright (c) 2017 Wind River Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.


Encryption Identification Scanner command line interface
"""

import sys

if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 4):
    print("Unsupported Python version " + str(sys.version))
    print("\nRequires Python version 3.4 or later.")
    sys.exit(1)

import traceback
from cryptodetector import CryptoDetector, Output, Options, Logger
from cryptodetector.exceptions import CryptoDetectorError

if __name__ == '__main__':

    try:
        log_output_directory = None
        options = Options(CryptoDetector.VERSION).read_all_options()
        if "log" in options:
            if options["log"]:
                log_output_directory = options["output"]
        CryptoDetector(options).scan()

        print("done")

    except CryptoDetectorError as expn:
        Output.print_error(str(expn))
        if log_output_directory: Logger.write_log_files(log_output_directory)

    except KeyboardInterrupt:
        raise

    except Exception as expn:
        Output.print_error("Unhandled exception.\n\n" + str(traceback.format_exc()))
        if log_output_directory: Logger.write_log_files(log_output_directory)
