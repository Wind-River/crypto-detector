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


  Exception subclasses
"""

class CryptoDetectorError(Exception):
    """Crypto Detector application error"""
    pass

class InvalidMethodException(CryptoDetectorError):
    """Invalid method class"""
    pass

class InvalidAPISyntaxException(CryptoDetectorError):
    """Invalid section syntax in api_patterns.txt"""
    pass

class InvalidKeywordList(CryptoDetectorError):
    """Invalid keyword list"""
    pass

class InvalidLanguageException(CryptoDetectorError):
    """Invalid or unsupported language"""
    pass

class InvalidRegexException(CryptoDetectorError):
    """Invalid regular expression"""
    pass

class InvalidOptionsException(CryptoDetectorError):
    """Invalid option in command line arguments"""
    pass

class InvalidConfigException(CryptoDetectorError):
    """Invalid config file"""
    pass

class InvalidPackageException(CryptoDetectorError):
    """Invalid package"""
    pass

class FileWriteException(CryptoDetectorError):
    """Error in writing a file"""
    pass

class ReadError(CryptoDetectorError):
    """Error in reading a file"""
    pass

class DownloadError(CryptoDetectorError):
    """Failure to download a file"""
    pass

class ExtractError(CryptoDetectorError):
    """Failure to extract an archive"""
    pass

class CompressionError(CryptoDetectorError):
    """Unavailable compression methods."""
    pass

class StreamError(CryptoDetectorError):
    """Unsupported operations on stream-like CpioFiles."""
    pass

class InvalidRPM(CryptoDetectorError):
    """Corrupt RPM files."""
    pass
