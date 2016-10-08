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
