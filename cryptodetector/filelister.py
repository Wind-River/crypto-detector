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

import shutil
import zipfile
import tarfile
import gzip
import bz2
import lzma
import re
import glob
import tempfile
import time
import os
from os.path import join, relpath, basename, abspath, exists, isfile, \
    isdir, dirname, normpath, islink
from os import pardir, makedirs, walk, remove
from urllib.request import urlopen, URLError, HTTPError
from urllib.parse import urlparse
from cryptodetector import Output, is_rpm, extract_rpm, Logger
from cryptodetector.exceptions import InvalidPackageException, ExtractError, \
    DownloadError, FileWriteException

class FileLister():
    """Class for gathering the list of files for each pacakge. A package can be a local archive,
    directory, wild-card address, link to a remote archive, or a git repository link.
    """
    GITHUB_REGEX = r"((?:git@github\.com\:)|(?:http[s]?://github.com/))" \
        + r"([^/]+)\/((?:(?!\.git)[^/])+)(?:\.git)?"

    all_temp_dirs = set()

    def __init__(self, packages,
                 skip_existing=False,
                 output_directory=None,
                 output_in_package_directory=False):
        """Initializer

        Args:
            packages: (list)
            skip_existing: (bool) whether we should skip listing package if output crypto file
                already exists.
            output_directory: (string)
            output_in_package_directory: (bool) whether output crypto file is placed in the same
                directory as the package.

        Returns:
            None
        """
        self.tmp_directories = set()
        FileLister.validate_package_list(packages)
        self.skip_existing = skip_existing
        self.output_directory = output_directory
        self.output_in_package_directory = output_in_package_directory

    def get_package_filelist(self, package):
        """Gather list of files in a package

        Args:
            package: (string) can specify a file, folder, wild-card, github, or a url

        Returns:
            (list) A list of file-lists, one file-list for each package found in `package` given
                above. In most cases, it is a list of only one file-list. But when package is a
                wild-card address, it can consist of multiple packages.

                A file-list is a dict object containing "package_name", "package_root", and
                "file_list". package_name is a string for name of the package, package_root is the
                directory containing the package (None if package is not a local one), and
                "file_list" is a list of in the package. A file is a dict with two keys
                "display_path" and "physical_path". "display_path" is the path that's shown to the
                user, but might not neccessarily be where the file physically resides, whereas
                "physical_path" is where file can be accessed. For example,
                "/path/arch.tar.gz/file.cpp" is a display_path, while "/tmp/cryptodetector/file.cpp"
                is the physcial_path.

                As an example, it could be:
                [{
                    "package_name": "test.tar.gz",
                    "package_root": "/home",
                    "file_list": [
                        {
                         "display_path": "/home/test.tar.gz/file1.cpp"
                         "physical_path": "/tmp/cryptodetector/file.cpp"
                        },
                        {
                         "display_path": "/home/test.tar.gz/file2.cpp"
                         "physical_path": "/tmp/cryptodetector/file2.cpp"
                        },
                        ...
                    ]
                }]
        """
        if isfile(package):
            return self.list_file(package)

        elif isdir(package):
            return self.list_directory(package)

        elif FileLister.is_wild_card(package):
            return self.list_wildcard(package)

        elif FileLister.is_github_address(package):
            return self.list_github_master(package)

        elif FileLister.is_url(package):
            return self.list_url(package)

    @staticmethod
    def validate_package_list(package_list):
        """Validate list of packages

        Args:
            package_list: (list) list of strings specifying packages

        Returns:
            None

        Raises:
            InvalidPackageException
        """
        for package in package_list:
            if not(isfile(package) or \
                   isdir(package) or \
                   FileLister.is_wild_card(package) or \
                   FileLister.is_github_address(package) or \
                   is_rpm(package) or \
                   FileLister.is_url(package)):
                raise InvalidPackageException("Invalid package: " + package \
                    + ". It wasn't a file, directory, an archive, " \
                    + "a wild-card expression, github address, or a URL.")

    def skip_package(self, package_name, package_root):
        """Check to see if we should skip listing this package if the crypto file already exists

        Args:
            package_name: (string) package name
            package_root: (string) the directory where package is located. If package is not
                a local one, this is None

        Returns:
            (bool) if we should skip listing this package
        """
        if not self.skip_existing:
            return False

        output_directory = self.output_directory
        if package_root and self.output_in_package_directory:
            output_directory = package_root

        crypto_file_path = join(output_directory, package_name + ".crypto")
        crypto_exists = isfile(crypto_file_path)

        if crypto_exists:
            skip_message = "Found a crypto file for package " \
                + package_name + " at " + crypto_file_path + ". Will skip scanning this package."
            Output.print_information(skip_message)
            Logger.log(skip_message)
        return crypto_exists

    def list_file(self, file_path, tmp_root_path="", current_path=""):
        """List a single file as package

        Args:
            file_path: (string) file path
            tmp_root_path: (string) if file is in a tmp directory, this is the address of that
                directory, otherwise null.
            current_path: (string) current address within the temporary directory. If we are not in
                a tmp directory, this is also null. This is used to compute the display path.

        Returns:
            (list) a list containing one file-list for this file.
        """
        archive_type = FileLister.archive_type(file_path)

        package_name = basename(file_path)
        package_root = abspath(dirname(file_path))

        if tmp_root_path:
            package_root = None

        if self.skip_package(package_name, package_root):
            return []

        # if this is itself a cyrpto file, don't list it as a package
        if file_path.split(".")[-1] == "crypto":
            Output.print_information("\nThe file " + file_path + " has a .crypto extention. " \
                + "This is reserved for the output of this program. Will not list this file " \
                + "as a package.")
            return []

        if tmp_root_path:
            display_path = join(current_path, relpath(file_path, tmp_root_path))
        else:
            display_path = abspath(file_path)

        if archive_type:
            tmp_dir = self.create_tmp_directory(package_name)
            FileLister.extract_archive(archive_type, file_path, display_path, tmp_dir)

            return self.list_directory(tmp_dir, package_name, tmp_root_path=tmp_dir, \
                current_path=display_path, _package_root=package_root)

        else:
            display_path = file_path
            if tmp_root_path:
                display_path = join(current_path, relpath(file_path, tmp_root_path))

            return [{
                "package_name": package_name,
                "package_root": package_root,
                "file_list": [{"display_path": display_path, "physical_path": file_path}]
            }]

    def list_directory(self, path, package_name=None, tmp_root_path="", current_path="", \
        _package_root=None):
        """List a directory as a package

        Args:
            path: (string) path of the directory
            package_name: (string) name of the package
            tmp_root_path: (string) if file is in a tmp directory, this is the address of that
                directory, otherwise null.
            current_path: (string) current address within the temporary directory. If we are not in
                a tmp directory, this is also null. This is used to compute the display path.
            _package_root: (string) when listing a local archive, this is used to keep track of its
                parent directory

        Returns:
            (list) a list containing one file-list for this directory.
        """
        if not package_name:
            package_name = basename(normpath(path))

        package_root = None
        if not tmp_root_path:
            package_root = abspath(join(path, pardir))
        elif _package_root:
            package_root = _package_root

        if self.skip_package(package_name, package_root):
            return []

        return [{
            "package_name": package_name,
            "package_root": package_root,
            "file_list": self.get_directory_filelist(path, tmp_root_path, current_path)
        }]

    def get_directory_filelist(self, path, tmp_root_path, current_path):
        """Recursively list all the files in a directory, extracting all the archives inside.

        Args:
            path: (string) path of the directory
            tmp_root_path: (string) if the directory is inside of a tmp directory, this is the
                address of that directory, otherwise null.
            current_path: (string) current address within the temporary directory. If we are not in
                a tmp directory, this is also null. This is used to compute the display path.

        Returns:
            (list) a list of files, where each file is a dict with two keys "display_path" and
            "physical_path". "display_path" is the path that's shown to the user and "physical_path"
            is where file can be accessed.
        """
        file_list = []

        for dirpath, _, filenames in walk(path, followlinks=False):
            for filename in filenames:
                full_path = abspath(join(dirpath, filename))
                if islink(full_path):
                    Output.print_warning("Skipping symbolic link: " + full_path)
                    continue

                archive_type = FileLister.archive_type(full_path)

                if archive_type:
                    tmp_dir = self.create_tmp_directory(full_path)

                    if tmp_root_path:
                        display_path = join(current_path, relpath(full_path, tmp_root_path))
                    else:
                        display_path = full_path

                    try:
                        FileLister.extract_archive(archive_type, full_path, display_path, tmp_dir)
                    except ExtractError as expn:
                        Output.print_error(str(expn))
                        continue

                    file_list.extend(self.get_directory_filelist(tmp_dir, \
                        tmp_root_path=tmp_dir, current_path=display_path))
                else:
                    if tmp_root_path:
                        file_list.append({
                            "display_path": join(current_path, relpath(full_path, tmp_root_path)),
                            "physical_path": full_path
                        })
                    else:
                        file_list.append({"display_path": full_path, "physical_path": full_path})

        return file_list

    def list_url(self, url):
        """List the file(s) at the given URL

        Args:
            url: (string)

        Returns:
            (list) a list containing one file-list for this url.
        """
        tmp_dir = self.create_tmp_directory(url)
        file_path = FileLister.download_file(url, tmp_dir)
        return self.list_file(file_path, tmp_root_path=tmp_dir)

    def list_github_master(self, github_address):
        """Download the master branch from GitHub and list it

        Args:
            github_address: (string)

        Returns:
            (list) a list containing one file-list for the master branch of this GitHub link
        """
        match = re.search(FileLister.GITHUB_REGEX, github_address)
        owner, repo = match.group(2), match.group(3)
        package_name = owner + "-" + repo + "-master"
        if self.skip_package(package_name, package_root=None):
            return []
        master_url = "https://github.com/" + owner + "/" + repo + "/archive/master.zip"
        tmp_dir = self.create_tmp_directory(master_url)
        master_zip_file = FileLister.download_file(master_url, tmp_dir)
        display_path = package_name + " /master.zip"
        FileLister.extract_zip(master_zip_file, display_path, tmp_dir)
        remove(master_zip_file)
        return self.list_directory(tmp_dir, package_name, tmp_dir)

    def list_wildcard(self, wildcard_path):
        """Add every path in the wild-card expansion

        Args:
            wildcard_path: (string)

        Returns:
            (list) a list of multiple file-lists, one for each package found in the
                wild-card address
        """
        result = []
        for path in glob.glob(wildcard_path):
            if isfile(path):
                result.extend(self.list_file(path))
            else:
                result.extend(self.list_directory(path))
        return result

    def list_rpm(self, rpm_file_path):
        """Extract an RPM archive and list its files.

        Args:
            rpm_file_path: (string)

        Returns:
            (list) a list containing one file-list containing all the files in the RPM archive
        """
        package_name = basename(rpm_file_path)
        tpm_dir = self.create_tmp_directory(package_name)
        FileLister.extract_rpm_archive(rpm_file_path, tpm_dir)
        return self.list_directory(tpm_dir, package_name, tpm_dir)

    @staticmethod
    def is_wild_card(path):
        """Determine if path is a wild-card address

        Args:
            path: (string)

        Returns:
            (bool) whether path is a wild-card address
        """
        return bool(next(glob.iglob(path), None))

    @staticmethod
    def is_github_address(address):
        """Determine if address is a github address

        Args:
            address: (string)

        Returns:
            (bool) whether address is a github address
        """
        return bool(re.search(FileLister.GITHUB_REGEX, address))

    @staticmethod
    def is_url(url):
        """Determine if a string is a valid URL

        Args:
            url: (string)

        Returns:
            (bool) whether the given url is valid
        """
        parsed_url = urlparse(url)
        return bool(parsed_url.scheme) and bool(parsed_url.netloc)

    @staticmethod
    def compression_library_reads(library, archive_path):
        """Checks to see if the given library can read the file at archive_path

        Args:
            library: (module)
            archive_path: (string)

        Returns:
            (bool)
        """
        try:
            with library.open(archive_path) as archive_file:
                compressed_payload = archive_file.read()
                return len(compressed_payload) > 5
        except:
            return False

    @staticmethod
    def archive_type(archive_path):
        """Determine if the file at archive_path is a compressed archive file

        Args:
            archive_path: (string)

        Returns:
            (string) the type of archive or None
        """

        archive_tests = [
            ("zip", lambda path: zipfile.is_zipfile(path)),
            ("tar", lambda path: tarfile.is_tarfile(path)),
            ("rpm", lambda path: is_rpm(path)),
            ("gzip", lambda path: FileLister.compression_library_reads(gzip, path)),
            ("bz2", lambda path: FileLister.compression_library_reads(bz2, path)),
            ("lzma", lambda path: FileLister.compression_library_reads(lzma, path))
            ]

        for archive_type_, archive_library in archive_tests:
            is_archive_file = False
            try:
                is_archive_file = archive_library(archive_path)
            except:
                pass
            if is_archive_file:
                return archive_type_

        return None

    @staticmethod
    def extract_archive(archive_type, full_path, display_path, tmp_dir):
        """Extract the given archive at tmp_dir"""
        if archive_type == "zip":
            FileLister.extract_zip(full_path, display_path, tmp_dir)
        elif archive_type == "tar":
            FileLister.extract_tar(full_path, display_path, tmp_dir)
        elif archive_type == "rpm":
            FileLister.extract_rpm_archive(full_path, display_path, tmp_dir)
        elif archive_type == "gzip":
            FileLister.extract_by_library(gzip, full_path, display_path, tmp_dir)
        elif archive_type == "bz2":
            FileLister.extract_by_library(bz2, full_path, display_path, tmp_dir)
        elif archive_type == "lzma":
            FileLister.extract_by_library(lzma, full_path, display_path, tmp_dir)

        # for some reason, when we get here, sometimes extraction is not fully finished, and
        # somemtimes it is. The operating systems sometimes isn't fully ready to read all the files.
        # Here we rename the parent directory to make extraction an atomic operation.
        while True:
            try:
                os.rename(tmp_dir, tmp_dir)
                break
            except:
                # This rename operating can fail. For example, when a file is still open
                # by another process, Windows will not allow anyone to rename the directory in which
                # that file resides. So here we sleep for one second to retry again.
                time.sleep(1)


    @staticmethod
    def extract_zip(zip_file_path, display_path, output_directory):
        """Extract a zip file

        Args:
            zip_file_path: (string) physical path of file on the hardware
            display_path: (string) file path that should be displayed to the user
            output_directory: (string)

        Returns:
            None

        Raises:
            ExtractError
        """
        Output.print_information("Extracting zip archive " + display_path + " ...")
        try:
            with zipfile.ZipFile(zip_file_path) as zip_file:
                zip_file.extractall(output_directory)
        except Exception as expn:
            raise ExtractError("Failed to extract zip archive " + display_path + "\n" + str(expn))

    @staticmethod
    def extract_tar(tar_file_path, display_path, output_directory):
        """Extract a tar archive

        Args:
            tar_file_path: (string) physical path of file on the hardware
            display_path: (string) file path that should be displayed to the user
            output_directory: (string)

        Returns:
            None

        Raises:
            ExtractError
        """
        Output.print_information("Extracting tar archive " + display_path + " ...")
        try:
            with tarfile.open(tar_file_path) as tar_file:
                tar_file.extractall(output_directory)
        except Exception as expn:
            raise ExtractError("Failed to extract tar archive " + display_path + "\n" + str(expn))

    @staticmethod
    def extract_by_library(library, archive_path, display_path, output_directory):
        """Extracts the given archive file to the output directory using the given library

        Args:
            library: (module)
            archive_path: (string) physical path of file on the hardware
            display_path: (string) file path that should be displayed to the user
            output_directory: (string)

        Returns:
            None

        Raises:
            ExtractError
        """
        library_name = library.__name__
        Output.print_information("Extracting " + library_name + " archive " \
            + display_path + " ...")

        try:
            with library.open(archive_path, "rb") as archive_file:
                decompressed_data = archive_file.read()

                # remove the extension from filename
                filename = basename(archive_path)
                if len(filename.split(".")) > 1:
                    filename = ".".join(filename.split(".")[:-1])

                with open(abspath(join(output_directory, filename)), "wb") as decomp_file:
                    decomp_file.write(decompressed_data)
        except Exception as expn:
            raise ExtractError("Failed to extract " + library_name + " archive " \
                + display_path + "\n" + str(expn))

    @staticmethod
    def extract_rpm_archive(archive_path, display_path, output_directory):
        """Extract RPM archive

        Args:
            archive_path: (string) physical path of file on the hardware
            display_path: (string) file path that should be displayed to the user
            output_directory: (string)

        Returns:
            None

        Raises:
            ExtractError
        """
        Output.print_information("Extracting RPM archive " \
            + display_path + " ...")
        try:
            extract_rpm(archive_path, output_directory)
        except Exception as expn:
            raise ExtractError("Failed to extract RPM archive " + display_path \
                + "\n\n" + str(expn))

    @staticmethod
    def download_file(url, download_directory):
        """Download a remote file

        Args:
            download_directory: (string)

        Returns:
            (string) that path of the file that was just downloaded. If something failed during
                download, return None

        Raises:
            DownloadError
        """
        Output.print_information("Downloading " + url + " ...")

        parsed_url = urlparse(url)
        if parsed_url.path in ["/", ""]:
            file_name = parsed_url.netloc
        else:
            file_name = parsed_url.path.split("/")[-1]
        download_path = abspath(join(download_directory, file_name))

        try:
            with open(download_path, 'wb') as file_object:
                file_object.write(urlopen(url).read())
                return download_path

        except HTTPError as expn:
            raise DownloadError("HTTP error code " + str(expn.code) + " while retrieving " \
             + url + "\n" + str(expn.reason))
        except URLError as expn:
            raise DownloadError("HTTP URL error while retrieving " + url + "\n" + str(expn.reason))
        except Exception as expn:
            raise DownloadError("Unable to retrieve " + url + "\n" + str(expn))

    def create_tmp_directory(self, dir_name):
        """Create a temporary directory

        Args:
            dir_name: (string) directory name

        Returns:
            (string) full path of the newly created tmp directory

        Raises:
            FileWriteException
        """
        tmp_dir_name = str(os.getpid()) + "-" + str(time.time())
        tmp_dir_name = join("cryptodetector", tmp_dir_name)
        tmp_dir = abspath(join(tempfile.gettempdir(), tmp_dir_name))

        try:
            if exists(tmp_dir):
                shutil.rmtree(tmp_dir)
            makedirs(tmp_dir)
        except Exception as expn:
            raise FileWriteException("Failed to create temporary directory " + tmp_dir \
                + "\n" + str(expn))
        else:
            self.tmp_directories.add(tmp_dir)
            FileLister.all_temp_dirs.add(tmp_dir)

        return tmp_dir

    def cleanup_tmp_folder(self):
        """Clean up temporary folder

        Args:
            None

        Returns:
            None
        """
        lose = set()
        # do not modify tmp_directories during the loop
        for tmp_dir in self.tmp_directories:
            if exists(tmp_dir):
                try:
                    shutil.rmtree(tmp_dir)
                except Exception as e:
                    Output.print_warning("Temp directory %s was not removed (%s)" % (tmp_dir,str(e)))
                else:
                    lose.add(tmp_dir)

        FileLister.all_temp_dirs -= lose
        self.tmp_directories -= lose
        Output.print_information("Temp dir count is %s %s" % (len(self.tmp_directories),len(FileLister.all_temp_dirs)) )

    @staticmethod
    def cleanup_all_tmp_files():
        """Clean up all temporary directories in case something went wrong during scan"""
        for tmp_dir in FileLister.all_temp_dirs:
            if exists(tmp_dir):
                try: 
                    shutil.rmtree(tmp_dir)
                except:
                    pass

