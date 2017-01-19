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
import configparser
import argparse
from cryptodetector import Output, MethodFactory
from cryptodetector.exceptions import InvalidMethodException, InvalidConfigException

class Options():
    """Read and parse options from config file and command line arguments
    """
    def __init__(self, version=""):
        """Initializer

        Args:
            version: (string)

        Returns:
            None
        """
        self.options = {
            "config_file": None,
            "methods": ["keyword", "api"],
            "output": os.getcwd(),
            "output_in_package_directory": False,
            "output_existing": "rename",
            "log": False,
            "pretty": False,
            "stop_after": None,
            "verbose": False,
            "quick": False,
            "source_files_only": False,
            "packages": [],
            "ignore_match_types": [],
            "suppress_warnings": False
            }

        self.options_help = {

            "config_file": "The path to the configuration file. If not provided, will" \
                + "look for `cryptodetector.conf` in the current directory (`cwd`), and if not " \
                + "found there, will try to find it in the home directory.",

            "methods": "List of space-seperated methods for searching the content of each file." \
                + " A method can be one of " \
                + str([method for method in Options.available_methods()]),

            "output": "The directory in which to write the output files. An output file is a " \
                + "[package].crypto for each package scanned. It contains the matches found in " \
                + "that package in JSON format.",

            "pretty": "Places indentation and additional spaces in the output crypto files " \
                + "to make them more readable (pretty) at the cost of producing larger files.",

            "stop_after": "Stop the search in a package after finding matches in this many of its" \
                + " files.",

            "verbose": "Verbosely process files and print out information during the search.",

            "quick": "Quickly search the  set of given packages and return only a list " \
                + "of packages that contain one or more matches",

            "packages": "Space-seperated list of packages to scan. They can be either a local " \
                + " directory, a compressed archive, a github address, or a URL pointing to a" \
                + "remote archive.",

            "ignore_match_types": "List of match types to ignore while searching for matches.",

            "suppress_warnings": "Option to not write warning messages",

            "output_in_package_directory": "With this option, the program will create output " \
                + "files in the directory in which the package resides. Note this will only " \
                + "work for local packages that have a directory.",

            "output_existing": "Specifies what to do when an output crypto file already exists. " \
                + "Can be one of three options: 'rename' (default) renames the new crypto file " \
                + ".0.crypto, .1.crypto  and so on, 'overwrite' overwrites the old file, and " \
                + "'skip' skips scanning the package.",

            "log": "Create event log and error log files at the end of each run.",

            "source_files_only": "Only scan source code files; ignore all other text files"
        }

        self.cmd_flags = {
            "config_file": "-c",
            "methods": "-m",
            "output": "-o",
            "stop_after": "-s",
            "verbose": "-v",
            "quick": "-q",
            "suppress_warnings": "-W",
            "output_in_package_directory": "-p"
        }

        self.method_options = {}
        self.version = version

    def _get_options(self):
        """Get list of options (for unit testing)

        Args:
            None

        Returns:
            (list) options
        """
        return self.options

    @staticmethod
    def available_methods():
        """Return a dict of available methods and their class objects

        Args:
            None

        Returns:
            (dict) method_id -> method_class
        """
        return {mc.method_id: mc for mc in MethodFactory.method_classes}

    @staticmethod
    def read_boolean_option(config, section, option):
        """Read a boolean option from a config file and return True or False

        Args:
            config: (configparser.ConfigParser)
            section: (string)
            option: (string)

        Returns:
            (bool) value of the option in the given section, or None if it doesn't exist
        """
        if not config.has_section(section):
            return

        return config.has_option(section, option)

    @staticmethod
    def read_string_option(config, section, option):
        """Read a string option from a config file and return its value

        Args:
            config: (configparser.ConfigParser)
            section: (string)
            option: (string)

        Returns:
            (string) value of the option in the given section or None if it doesn't exist
        """
        if not config.has_section(section) or not config.has_option(section, option):
            return

        return config.get(section, option)

    @staticmethod
    def read_array_option(config, section):
        """Read an array from a config file and return its value

        Args:
            config: (configparser.ConfigParser)
            section: (string)

        Returns:
            (list) values in the array, or None if section doesn't exist
        """
        if not config.has_section(section):
            return

        return [item for item, _ in config.items(section)]


    def parse_cmd_argument(self, parser, option, additional_args=None):
        """Updates parser with with the given option and additional args

        Args:
            parser: (argparse.ArgumentParser)
            option: (string)
            additional_args: (dict)

        Returns:
            None
        """
        call_args_iterable = []
        call_args_kw = {}

        if option in self.cmd_flags:
            call_args_iterable.append(self.cmd_flags[option])

        call_args_iterable.append("--" + option.replace("_", "-"))

        call_args_kw["dest"] = option
        call_args_kw["default"] = None

        if option in self.options_help:
            call_args_kw["help"] = self.options_help[option]

        if additional_args:
            call_args_kw.update(additional_args)

        parser.add_argument(*call_args_iterable, **call_args_kw)

    @staticmethod
    def validate_methods(methods):
        """Validate list of methods

        Args:
            methods: (list)

        Returns:
            None

        Raises:
            InvalidMethodException
        """
        if not methods:
            return

        for method in methods:
            if method not in Options.available_methods():
                raise InvalidMethodException("Invalid method: '" + method +  \
                    "'. No method was found with this method_id. Valid choices for method are " +
                    str([method for method in Options.available_methods()]))

    def get_parsed_cmd_args(self, test_case=None):
        """Parse command line arguments

        Args:
            test_case: (dict) used internally for unit-testing

        Returns:
            (dict) key,value dict of all command line options
        """

        class BooleanAction(argparse.Action):
            """Custom action for storing boolean options
            """
            def __init__(self, *args, **kwargs):
                super(BooleanAction, self).__init__(*args, **kwargs)

            def __call__(self, parser, namespace, value, option_string):
                setattr(namespace, self.dest, value not in ["False", "false"])

        class ArrayAction(argparse.Action):
            """Custom action for storing comma seperated arrays
            """
            def __init__(self, *args, **kwargs):
                super(ArrayAction, self).__init__(*args, **kwargs)

            def __call__(self, parser, namespace, value, option_string):
                setattr(namespace, self.dest, value.split(","))

        argument_parser = argparse.ArgumentParser(
            description="Encryption identification scanner: " \
            + "scans a set of packages to detect use of encryption algorithms.",
            epilog="For additional information, visit: " \
            + "https://github.com/Wind-River/crypto-detector")

        argument_parser.add_argument("--version", \
            action='version', version=self.version)

        # automatically generate options for methods

        for method in Options.available_methods():

            method_class = Options.available_methods()[method]

            if not hasattr(method_class, "options"):
                continue

            for option in method_class.options:
                self.options[method + "_" + option] = method_class.options[option]
                self.method_options[method + "_" + option] = (method, option)

            if hasattr(method_class, "options_help"):
                self.options_help.update({
                    method + "_" + option: method_class.options_help[option] \
                    for option in method_class.options_help})

        for option in self.options:

            if option == "packages":
                continue

            additional_args = {}

            if isinstance(self.options[option], list):
                additional_args["action"] = ArrayAction

            elif isinstance(self.options[option], bool):
                additional_args["nargs"] = "?"
                additional_args["choices"] = ["True", "true", "False", "false"]
                additional_args["action"] = BooleanAction

            elif option == "output_existing":
                additional_args["choices"] = ["rename", "overwrite", "skip"]

            self.parse_cmd_argument(argument_parser, option, additional_args)

        argument_parser.add_argument(nargs='*', dest="packages", help=self.options_help["packages"])

        if test_case:
            return vars(argument_parser.parse_args(test_case))

        return vars(argument_parser.parse_args())

    def read_config_file(self, path):
        """Read configuration file and update self.options

        Args:
            path: (string) path of the config file

        Returns:
            None

        Raises:
            InvalidConfigException
        """
        config = configparser.ConfigParser(allow_no_value=True, delimiters=('='))
        config.optionxform = str

        if path:
            path_conf = os.path.abspath(path)
            Output.print_information("Reading configuration file " + path_conf, True)
            if not os.path.isfile(path_conf):
                raise InvalidConfigException("The specified config file doesn't exist.")
            config.read(path_conf)

        else:
            home_directory = os.path.expanduser("~")
            cwd_conf = os.path.abspath(os.path.join(os.getcwd(), "cryptodetector.conf"))
            home_conf = os.path.abspath(os.path.join(home_directory, "cryptodetector.conf"))

            # Does config file exist in current working directory?
            if os.path.isfile(cwd_conf):
                Output.print_information("Reading configuration file " + cwd_conf, True)
                self.options["config_file"] = cwd_conf
                config.read(cwd_conf)

            # Does config file exist in home folder ?
            elif os.path.isfile(home_conf):
                Output.print_information("Reading configuration file " + home_conf, True)
                self.options["config_file"] = home_conf
                config.read(home_conf)

            else:
                Output.print_information("Didn't find any configuration file. Expect all " \
                    + "parameters from the command line.", True)
                return

        for section in ["settings", "methods"]:
            if section not in config.sections():
                raise InvalidConfigException("Invalid configuration file. [" \
                    + section + "] section " + "is required.")

        for option in self.options:

            if isinstance(self.options[option], list):
                option_value = Options.read_array_option(config, option)

            elif isinstance(self.options[option], bool):
                option_value = Options.read_boolean_option(config, "settings", option)

            else:
                option_value = Options.read_string_option(config, "settings", option)

            if option_value != None:
                self.options[option] = option_value

        for option in ["methods", "packages"]:
            if config.has_section(option):
                self.options[option] = [item for item, _ in config.items(option)]

        if self.options["output_existing"] not in ["rename", "overwrite", "skip"]:
            raise InvalidConfigException("Invalid config file. In section [settings] " \
                + "output_existing had invalid value '" + self.options["output_existing"] \
                + "'. Its value must be one of three choices: " \
                + "'rename', 'overwrite', and 'skip'.")

        if not self.options["methods"]:
            raise InvalidConfigException("Invalid configuration file. There should be one " \
                + "or more items under the [methods] section.")

        methods = self.options["methods"]
        Options.validate_methods(methods)

        for method in methods:
            method_class = Options.available_methods()[method]

            if not hasattr(method_class, "options"):
                continue

            for option in method_class.options:
                if isinstance(method_class.options[option], list):
                    option_value = Options.read_array_option(config, "method:" \
                        + method + ":" + option)

                elif isinstance(method_class.options[option], bool):
                    option_value = Options.read_boolean_option(config, "method:" + method, option)

                else:
                    option_value = Options.read_string_option(config, "method:" + method, option)

                if option_value != None:
                    method_class.options[option] = option_value
                    self.options[method + "_" + option] = option_value

    def read_all_options(self, test_case=None):
        """Return list of all options

        Args:
            test_case: (dict) used internally for unit-testing

        Returns:
            (dict) all options
        """
        args = self.get_parsed_cmd_args(test_case)

        Options.validate_methods(args["methods"])

        self.read_config_file(args["config_file"])

        for option in self.options:
            if args[option] not in [None, []]:
                self.options[option] = args[option]

                if option in self.method_options:
                    method, method_option = self.method_options[option]
                    Options.available_methods()[method].options[method_option] = args[option]

        #remove duplicate
        for option in ["methods", "packages"]:
            self.options[option] = list(set(self.options[option]))

        return self.options
