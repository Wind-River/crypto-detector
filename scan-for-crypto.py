#!/usr/bin/python3

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


Encryption Identification Scanner command line interface
"""

import sys

if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 5):
    print("Unsupported Python version " + str(sys.version))
    print("\nRequires Python version 3.5 or later.")
    sys.exit(1)

from cryptodetector import CryptoDetector, Output, Options
from cryptodetector.exceptions import CryptoDetectorError

if __name__ == '__main__':

    try:
        options = Options(CryptoDetector.version()).read_all_options()
        CryptoDetector(options).scan()

        print("done")

    except CryptoDetectorError as expn:
        Output.print_error(str(expn))

    except KeyboardInterrupt:
        raise

    except Exception:
        Output.print_error("Unhandled exception.")
        raise
