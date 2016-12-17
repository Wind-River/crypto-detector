"""
Copyright (c) 2016 Wind River Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.
"""

from os.path import dirname, realpath, join, basename, isfile
from os import listdir

from cryptodetector.logger import Logger
from cryptodetector.languages import Languages
from cryptodetector.output import Output
from cryptodetector.regex import Regex
from cryptodetector.rpm import is_rpm, extract_rpm
from cryptodetector.filelister import FileLister
from cryptodetector.method import Method, MethodFactory
from cryptodetector.options import Options
from cryptodetector.cryptodetector import CryptoDetector
#
#  Dynamically import all the methods
#
ROOT_DIR = join(dirname(realpath(__file__)), "methods")
for method in listdir(ROOT_DIR):
    for method_module in listdir(join(ROOT_DIR, method)):
        if not method_module.endswith(".py"):
            continue
        module_path = ".".join(["cryptodetector", "methods", method, method_module[:-3]])
        __import__(module_path)
