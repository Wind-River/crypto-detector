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
import sys
import hashlib
import codecs
import mimetypes
import json
import copy
import re
import time
import platform
from cryptodetector import Method, MethodFactory, Language, Output, FileLister, Logger, \
    CryptoOutput
from cryptodetector.exceptions import InvalidOptionsException, FileWriteException, \
    InvalidMethodException, FailedFileRead


class CryptoDetector(object):
    """Cryptography Detector main class
    """

    VERSION = "0.2 development"


    def __init__(self, options, skip_output=False):
        """
        Args:
            options: (dict)
            skip_output: (bool) whether we should skip writing or printing out the output (used only
                for unit testing)

        Returns:
            None

        Raises:
            InvalidOptionsException
        """
        try:
            for option in ["output", "quick", "output_in_package_directory", "output_existing", \
                "pretty", "log", "source_files_only"]:
                setattr(self, option, options[option])
            self.output_directory = self.output
            Method.ignore_evidence_types = options["ignore_evidence_types"]
            Output.verbose = options["verbose"]
            Output.suppress_warnings = options["suppress_warnings"]
            stop_after = options["stop_after"]
            packages = options["packages"]
            methods = options["methods"]
        except KeyError as expn:
            raise InvalidOptionsException("Missing required option: \n" + str(expn))

        self.packages = packages
        self.quick_scan_result = {}
        self.full_scan_result = {}
        self.skip_output = skip_output
        self.current_package = None
        self.stop_after = None

        if stop_after:
            try:
                self.stop_after = int(stop_after)
            except:
                raise InvalidOptionsException("Invalid stop_after value: '" + stop_after + "'.")
            if self.stop_after < 1:
                raise InvalidOptionsException("stop_after should be a positive integer.")

        if not os.path.isdir(self.output_directory):
            raise InvalidOptionsException("The specified output directory doesn't exist: " \
                + self.output_directory)

        if not packages:
            Output.print_information("\nNo package specified. Nothing to scan.\n", \
                ignore_verbose=True)
            return

        if self.output_existing not in ["rename", "overwrite", "skip"]:
            raise InvalidOptionsException("output_existing had invalid value '" \
                + self.output_existing + "'. Its value must be one of three choices: " \
                + "'rename', 'overwrite', and 'skip'.")

        self.file_lister = FileLister(packages, (self.output_existing == "skip"), \
            self.output_directory, self.output_in_package_directory)

        method_classes = {mc.method_id: mc for mc in MethodFactory.method_classes}

        method_instances = {}

        for method in method_classes:

            # instantiate method
            method_instances[method] = method_classes[method]()

            # read options
            method_options = None
            if hasattr(method_instances[method], "options"):
                method_options = method_instances[method].options

            if method == "keyword":
                self.method_keyword_active = (method in methods)
                self.method_keyword_ignore_case = method_options["ignore_case"]
                self.method_keyword_kwlist_version = method_options["keyword_list_version"]

            elif method == "api":
                self.method_api_active = (method in methods)
                self.method_api_kwlist_version = method_options["keyword_list_version"]

        # active methods are the ones we use to scan the code

        self.active_methods = {}
        for method in methods:
            if method not in method_classes:
                raise InvalidOptionsException("Invalid method " + method)

            self.active_methods[method] = method_instances[method]

    def scan(self):
        """Main function to initiate the scanning job

        Args:
            None

        Returns:
            None
        """
        if not self.packages:
            return

        Logger.log("Crypto Detector " + CryptoDetector.VERSION + " (c) Wind River Systems")
        Logger.log(("{} "*6).format(platform.system(), platform.node(), platform.release(), \
            platform.version(), platform.machine(), platform.processor()))
        Logger.log("Python " + str(platform.python_version()))
        Logger.log("")
        Logger.log("")
        Logger.log("Starting a new crypto scanning job with the following options:")

        Logger.log("source_files_only: " + str(self.source_files_only))
        Logger.log("stop_after: "+ str(self.stop_after))
        Logger.log("output_existing: "+ str(self.output_existing))
        Logger.log("ignore_evidence_types: "+ str(Method.ignore_evidence_types))

        if self.method_keyword_active:
            Logger.log("keyword method is active keyword list version " \
                + str(self.method_keyword_kwlist_version) + " and ignore_case set to " \
                + str(self.method_keyword_ignore_case))

        if self.method_api_active:
            Logger.log("API method is active with api list version " \
                + str(self.method_api_kwlist_version))

        package_count = 0
        total_execution_time = 0
        total_text_bytes = 0
        total_binary_bytes = 0
        total_file_count = 0
        total_lines_of_text = 0

        for package_path in self.packages:
            package_filelist = self.file_lister.get_package_filelist(package_path)

            for package in package_filelist:
                package_name = package["package_name"]
                package_root = package["package_root"]
                file_list = package["file_list"]
                sha1_list = []
                package_count += 1
                match_count = 0
                checksums = {}
                crypto_output = CryptoOutput()

                self.current_package = package_name
                self.package_text_bytes = 0
                self.package_binary_bytes = 0
                self.package_lines_of_text = 0

                crypto_output.set_package_name(package_name)

                Output.print_information("Scanning package " + package_name + "\n")

                start_time = time.time()
                stats = {}
                self.package_text_bytes = 0
                self.package_binary_bytes = 0
                self.package_lines_of_text = 0

                if self.quick and package_name not in self.quick_scan_result:
                    self.quick_scan_result[package_name] = False

                for file_path in file_list:
                    content, language = self.read_file(file_path["physical_path"])

                    if content is None:
                        raise FailedFileRead("Failed to open the file '" + file_path["display_path"] \
                            + "' to read its contents. Please run the scan with --log and open the log" \
                            + " file for details of this error.")

                    if isinstance(content, str):
                        encoded_content = codecs.encode(content, "utf-8")
                    else:
                        encoded_content = content

                    hexdigest = hashlib.sha1(encoded_content).hexdigest()
                    sha1_list.append(hexdigest)

                    found_matches = False

                    for method_id in self.active_methods:
                        method = self.active_methods[method_id]

                        if not method.supports_scanning_file(language):
                            continue

                        if self.source_files_only and not language.is_source_code:
                            continue

                        Output.print_information("[" + method.method_id \
                            + "] Scanning file " + file_path["display_path"])


                        if self.quick:
                            if method.quick_search(content, language):
                                found_matches = True
                                break
                        else:
                            result = method.search(content, language)

                            if not result:
                                continue
                            else:
                                found_matches = True

                            if file_path["display_path"] not in checksums:
                                checksums[file_path["display_path"]] = hexdigest

                            for match in result:
                                match["detection_method"] = method_id
                                match = self.validate_match_fields(method_id, match)
                                crypto_output.add_hit(
                                    file_path=file_path["display_path"],
                                    file_sha1=checksums[file_path["display_path"]],
                                    file_language=language,
                                    hit=match)
                                match_count += 1

                    if self.quick:
                        if found_matches:
                            self.quick_scan_result[package_name] = True
                            break
                    else:
                        self.full_scan_result[package_name] = crypto_output.get_crypto_data()

                    if self.stop_after and found_matches:
                        if self.stop_after == 1:
                            break
                        else:
                            self.stop_after -= 1

                crypto_output.set_verif_code(sha1_list)

                stats["execution_time"] = time.time() - start_time
                stats["file_count"] = len(file_list)
                stats["package_text_bytes"] = self.package_text_bytes
                stats["package_binary_bytes"] = self.package_binary_bytes
                stats["package_lines_of_text"] = self.package_lines_of_text

                if package_root != None and self.output_in_package_directory:
                    output_directory = package_root
                else:
                    output_directory = self.output_directory

                # write the output to a file

                if not self.skip_output and not self.quick:
                    self.write_crypto_file(crypto_output.get_crypto_data(),
                                           output_directory, package_name)

                number_of_matches = "Did not find any matches"
                if match_count == 1:
                    number_of_matches = "Found only one match"
                elif match_count > 1:
                    number_of_matches = "Found " + str(match_count) + " matches"

                Logger.log("")
                Logger.log("Finished scanning package " + package_name + " in " \
                    + str(round(stats["execution_time"], 2)) + " seconds.")
                Logger.log("There were " + str(stats["file_count"]) + " files consisting of " \
                    + str(stats["package_lines_of_text"]) + " lines of text in " \
                    + CryptoDetector.human_readable_filesize(stats["package_text_bytes"]) \
                    + " of text data and " \
                    + CryptoDetector.human_readable_filesize(stats["package_binary_bytes"]) \
                    + " of binary data.")
                Logger.log(number_of_matches + " in " + package_name)

                total_execution_time += stats["execution_time"]
                total_file_count += stats["file_count"]
                total_text_bytes += stats["package_text_bytes"]
                total_binary_bytes += stats["package_binary_bytes"]
                total_lines_of_text += stats["package_lines_of_text"]

                Output.print_information("\nCleaning up temporary files ...")
                self.file_lister.cleaup_tmp_folder()

        # write quick scan output to stdout and some output file

        if self.quick and not self.skip_output:
            output_message = ""
            if not any([self.quick_scan_result[package] for package in self.quick_scan_result]):
                output_message += "\n\nDid not find any matches in any of the packages.\n\n"
            else:
                output_message += "\n\nFound matches in the following packages:\n\n"
                for package in self.quick_scan_result:
                    if self.quick_scan_result[package]:
                        output_message += "    " + package + "\n"
                output_message += "\n\n"

                print(output_message)

                # write quick search output to a file
                quick_output_filename = os.path.join(self.output_directory, \
                   "quick-scan-result.txt")

                with open(quick_output_filename, "w") as output_file:
                    output_file.write(output_message)

        # print stats

        Output.print_information("\nTook " \
            + str(round(total_execution_time, 2)) + " seconds to scan " \
            + str(total_file_count) + " files in " \
            + str(package_count) + " package" \
            + ("s" if package_count > 1 else "") + ", processing " \
            + str(total_lines_of_text) \
            + " lines of text in " \
            + CryptoDetector.human_readable_filesize(total_text_bytes) \
            + " of text data, in addition to scanning " \
            + CryptoDetector.human_readable_filesize(total_binary_bytes) \
            + " of binary data.")

        if self.log:
            Logger.write_log_files(self.output_directory)

        if self.quick:
            return self.quick_scan_result
        else:
            return self.full_scan_result

    def validate_match_fields(self, method_id, match_dict):
        """Validate the output fields of the match. If something is missing (but not required), it
        will be added to the match object. If the field is required, InvalidMethodException will be
        thrown

        Args:
            method_id: (string)
            match_dict: (dict)

        Returns:
            A match dict with the expected fields added as blank

        Raises:
            InvalidMethodException
        """
        match_dict_with_missing_fields = copy.copy(match_dict)
        EMPTY_VALUE = ""

        for required_field in CryptoOutput.required_output_fields():
            if required_field not in match_dict:
                if CryptoOutput.required_output_fields()[required_field]:
                    raise InvalidMethodException("Invalid Method " + method_id \
                        + ". Missing required output field '" \
                        + required_field + "' in the match object.")
                else:
                    match_dict_with_missing_fields[required_field] = EMPTY_VALUE
        return match_dict_with_missing_fields


    def write_crypto_file(self, json_data, output_directory, package_name):
        """Writes the crypto data to a file at the output_directory
            Args:
                json_data: (dict)
                output_directory: (string)
                package_name: (string)

            Returns:
                None

            Raises:
                FileWriteException
        """
        output_file = os.path.join(output_directory, package_name)

        if self.output_existing == "rename":
            duplicate_number = 1
            duplicate_file = output_file
            while os.path.exists(duplicate_file + ".crypto"):
                duplicate_file = output_file + "." + str(duplicate_number)
                duplicate_number += 1
            output_file = duplicate_file + ".crypto"
        else:
            output_file += ".crypto"

        Output.print_information("\nWriting output in " + output_file + " ...\n")

        output_file += ".partial"

        try:
            with open(output_file, 'w') as file_object:

                if self.pretty:
                    JSON_string = json.dumps(json_data, sort_keys=True, indent=2)
                else:
                    JSON_string = json.dumps(json_data)

                file_object.write(JSON_string)

        except (OSError, IOError) as e:
            raise FileWriteException("Failed to write result in the crypto file " + output_file \
                + "\n" + str(e))

        # rename the file back from .crypto.partial to .crypto at the very last step to ensure
        # writing completely succeeded when a .crypto file exists
        crypto_file_path = output_file[:-8]
        if os.path.exists(crypto_file_path):
            os.remove(crypto_file_path)
        os.rename(output_file, crypto_file_path)

    @staticmethod
    def human_readable_filesize(size):
        """Print file size in human readable format

        Args:
            size: (int)

        Returns:
            (string) A human readable string of the size
        """
        for unit in [' bytes', ' KiB', ' MiB', ' GiB', ' TiB', ' PiB', ' EiB']:
            if size < 1024.0:
                return str(round(size, 2)) + unit
            size /= 1024.0

    @staticmethod
    def has_nontext_characters(content):
        """Determine if the characters in a file are outside the scope of text file characters as defined here:
        https://github.com/file/file/blob/f2a6e7cb7db9b5fd86100403df6b2f830c7f22ba/src/encoding.c#L151-L228

        Args:
            content: (string)

        Returns:
            (bool)
        """
        text_chars = set([7, 8, 9, 10, 11, 12, 13, 27]) | set(range(0x20, 0x100)) - set([0x7f])
        return bool(content.translate({c: None for c in bytearray(text_chars)}))

    def read_text_file(self, path):
        """Try multiple different text encodings to read a text file

        Args:
            path: (string) file path

        Returns:
            (string, string) the content of the file and its encoding
            None if it failed to read the file
        """
        text_encodings = ["utf-8", "latin-1", "iso-8859-1", "utf-16", "utf-32", "cp500"]
        content = None

        for encoding in text_encodings:
            try:
                with open(path, 'r', encoding=encoding) as content_file:
                    content = content_file.read()
                    break

            except ValueError as expn:
                continue

            except (OSError, IOError) as expn:
                Output.print_error("Critical error while reading file " + path + "\n" + str(expn))
                return content

            except Exception as expn:
                Output.print_error("Exception while opening file " + path + "\n" + str(expn))
                return content

        return content

    def read_binary_file(self, path):
        """Read a binary file

        Args:
            path: (string) file path

        Returns:
            (bytes) raw bytes sequence in the binary file
            None if it failed to read the file
        """
        content = None

        try:
            with open(path, 'rb') as content_file:
                content = content_file.read()

        except (OSError, IOError) as expn:
            Output.print_error("Critical error while reading file " + path + "\n" + str(expn))
            return content

        except Exception as expn:
            Output.print_error("Couldn't open binary file " + path + "\n" + str(expn))
            return content

        return content

    def read_file(self, path):
        """Reads a file at the given path to return its content and language

        Args:
            path: (string) file path

        Returns:
            tuple (file content, language) file content is either a str or bytes array depending
                on whether or not it is binary.
        """
        content = None

        filename, file_extension = os.path.splitext(path)
        file_extension = file_extension.split(".")[-1].lower()

        language = Language.guess_language(file_extension)

        if language == Language.Unknown:

            # if we couldn't guess the type of the file from its extension, try to open it
            # as plain text, and if that failed, treat it as binary, but if that succeeded,
            # check the characters in the file to ensure it is a text file.

            content = self.read_text_file(path)

            if content is None:
                content = self.read_binary_file(path)
                language = Language.Binary

            else:
                if self.has_nontext_characters(content):
                    content = self.read_binary_file(path)
                    language = Language.Binary
                else:
                    language = Language.PlainText

        else:
            if language.is_text:
                content = self.read_text_file(path)

                if content is None:
                    Output.print_error("Couldn't decode the text file " + \
                        path + "using any of Unicode, Latin, ISO-8859, or EBCDIC encodings." + \
                        " Will treat as binary.")
                    content = self.read_binary_file(path)
                    language = Language.Binary
            else:
                content = self.read_binary_file(path)
                language = Language.Binary


        if content is not None:
            if language == Language.Binary:
                self.package_binary_bytes += len(content)
            else:
                self.package_text_bytes += len(content)
                self.package_lines_of_text += len(content.split("\n"))

        return content, language
