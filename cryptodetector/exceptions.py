"""
Copyright (c) 2017 Wind River Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.


Exception subclasses
"""

class CryptoDetectorError(Exception):
    """Crypto Detector application error"""
    pass

class FailedFileRead(CryptoDetectorError):
    """Failed to read a file. All files must be read so that verification code
    could b ecomputed correctly"""
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
