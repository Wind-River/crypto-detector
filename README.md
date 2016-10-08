#Encryption Identification Scanner#

## Overview ##

Detecting cryptography algorithms in the source code of packages or libraries turns out to be a common problem for many of the software companies that include these packages in their products.

At Wind River, we face a similar challenge. Thousands of packages are bundled as part of the Wind River operating system. We are developing this project to be an automated and efficient code parser that can determine, with some degree of confidence, that a piece of code contains restricted encryption algorithms. The output could then be verified by a human expert.


## Methods of scanning code ##

More often than not, a source code that contains encryption algorithms uses words that are very related to that algorithm. So as a start, we can scan the source code searching for these keywords, like "DES_" or "TLSv1". This is a simple, first-pass that gives us an initial idea as to whether or not the source code might contain encryption algorithms.

To go one step further, we search the content of each file for patterns (expressed in in a regular expression). These could be API calls to a crypto library, an include file, a line of code that happens frequently in encryption, or similar patterns.

## Encryption algorithms ##

Currently, our code crudely detects the following cryptography schemes:

* Asymmetric cryptography:
  * RSA, DSA, Diffie-Hellman, ECC, ElGamal
* Block ciphers:
  * AES, DES, RC2, RC5, RC6, CAST, Blowfish, Twofish, Threefish, Camellia, IDEA, GOST, IntelCascade, KASUMI, MISTY1, NOEKEON, SEED, Serpent, XTEA, BEAR-LION
* Stream ciphers:
  * RC4, Salsa20, ChaCha20
* Hybrid encryption:
  * PGP, GPG
* Hashing algorithms:
  *  MD2, MD4, MD5, SHA1, SHA-256, SHA-2, BLAKE, HMAC, RIPEMD, Tiger, Whirlpool
* Protocols and standards:
  * SSL, TLS, SSH, PKI, MQV, kerberos
* Encryption libraries:
  * OpenSSL, OpenSSH, libgcrypt, Crypto++, BeeCrypt, Botan, BouncyCastle, SpongyCastle
* Generic encryption evidence

## Using this tool ##

The script is written in Python and requires Python version 3.4 or later to be installed.

### Installing Python ###

#### Debian based Linux ####
To install Python, run the following command:

```
sudo apt-get install python3
```

#### Windows ####
Download the latest Python 3 release from https://www.python.org/downloads/windows/ and install it using the installation wizard.

#### Apple OS X ####
If you have homebrew installed, simply run

```
sudo brew install python3
```
Otherwise, you can download the latest Python 3 release from https://www.python.org/downloads/mac-osx/ and install it that way.

### Running the script ###

To run the script, exectute

```
python3 scan-for-crypto.py <options> <packages>
```

Note: on Windows, the executable is called "python.exe", so put that in place of "python3". You can create an alias with the command `doskey python3=C:\path\to\python.exe $*` so instead of typing the full path to python.exe, you could use the alias 'python3'.

####Packages####
Space-separated list of packages to scan. A package can be given as a path to a local directory, a local file, a local compressed archive, wild-card address, a emote archive, url to a single source file, or a GitHub link. Have a look at `cryptodetector.conf` file for list of examples.

####Options####
#####--config-file=`<file path>` or -c `<file path>`#####
The path to the configuration file. If a configuration file is present, all options will be read from this file first, with additional command line arguments overriding them. Next section covers the specifications of a configuration file.

#####--methods=`<list of one or more methods>` or -m `<list of one or more methods>`#####
Specifies the methods of scanning. Accepts a comma-separated list of methods. A method can be one of `keyword` or `api`, pertaining to the keyword search and API pattern finder respectively.

#####--quick or -q or --quick=`<True|False>`#####
Performs a quick/express search on a set of packages, returning a list of packages with one or more matches found in any of their files.

#####--stop-after=k or -s k#####
Specifies to stop the search during execution of each method after finding `k` files with matches in them.

#####--keyword-ignore-case or --keyword-ignore-case=`<True|False>`#####
Makes the keyword search case-insensitive.

#####--api-ignore-case or --api-ignore-case=`<True|False>`#####
Makes the API finder case-insensitive.

#####--ignore-match-types=`<list of match types>`#####
Comma-separated list of match types to ignore while searching files for matches.

#####--output=`<path to directory>` or -o `<path to directory>`#####
Specifies the path in which the output files should be written. If this option is not provided, the default value is the current working directory.

#####--output-in-package-directory or -p or --output-in-package-directory=`<True|False>`#####
With this option, the program will create output files in the directory in which the package resides. Note this will only work for local packages that have a directory.

#####--output-existing=`<rename|overwrite|skip>`#####
Specifies what to do when an output crypto file already exists. Can be one of three options: 'rename' (default) renames the new crypto file .0.crypto, .1.crypto and so on, 'overwrite' overwrites the old file, and 'skip' skips scanning the package.

#####--pretty or --pretty=`<True|False>`#####
Places indentation and additional spaces in the output crypto files to make them more readable (pretty) at the cost of producing larger files.

#####--verbose or -v or --verbose=`<True|False>`#####
Specifies whether to verbosely processes files and print out information.

#####--suppress-warnings or -W or --suppress-warnings=`<True|False>`#####
Specifies not to write warning messages.

#####--version#####
Shows the version of this program.

#####--help or -h#####
Shows a help guide.

####Configuration File####
A configuration file contains all the options to the program, so one doesn't have to type them out in the command line every time. The path to the configuration file could be specified by the option `--config-file` or `-c` as specified above.

If this option is not present, this program will look for the file `cryptodetector.conf` in the *current working directory*. This is the directory in which the command line interpreter works, not neccessarily the directory where this script is saved.

If the configuration file is not found there, it looks for it in the home folder. In Unix and Unix-like systems, this is the directory referred to as `~/`. In Windows, this is the `%UserProfile%` directory. Depending on the version of Windows, that could be one of `<drive>:\Documents and Settings\<user>` or ` <drive>:\Users\<user>` .

If no config file is found, the program expects all the parameters from the command line.

Look at the example file `cryptodetector.conf` for the syntax. It is the same syntax as most other configuration files, where sections are enclosed by brackets and items are under sections, line by line. If an item has a value, its value is provided by the equal sign. Commenting out a line is simply putting a `#` sign in front of it.

####Examples####

To scan a single package (with default keyword search)

```
python3 scan-for-crypto.py /path/to/root/of/package
```

To scan two packages with keyword search and API finder

```
python3 scan-for-crypto.py --methods=keyword,api /path/to/package1 /path/to/package2
```

To download, extract, and scan the content of an archive using the API method, stopping the search after finding patterns in at most 4 files

```
python3 scan-for-crypto.py --methods=api --stop-after=4 http://url/of/archive.tar.gz2
```

To scan the master branch of a public GitHub repository:

```
python3 scan-for-crypto.py https://github.com/godbus/dbus.git
```

To write output files to a different directory:

```
python3 scan-for-crypto.py --output=/output/path /path/to/a/compressed/archive.tar.gz2
```

To scan a folder containg tar archives:

```
python3 scan-for-crypto.py /folder/*.tar.gz
```

### The Output ###
This script creates a set of `<package>.crypto` files for each package that it scans. It writes a json object in this file that is the list of matches it found in the package. The matches are organized by relative file path. The json is a key-value object, where keys are filenames and values are an array of matches. It looks like this (condensed for readability):

```
{
  "errors": [],
  "stats": {
    "bytes_of_binary_processed": 777261,
    "bytes_of_text_processed": 25225060,
    "execution_time": 39.30186676979065,
    "file_count": 2394,
    "lines_of_text_processed": 743384
  }
  "report": {
    "/openssl-1.0.2d/.pc/Makefiles-ptest.patch/Makefile.org": {
      "SHA1_checksum": "c309254506b4f824b9330774071b67b3479c54b8",
      "matches": [
        {
          "line_text": "INSTALLTOP=/usr/local/ssl",
          "line_text_after_1": "",
          "line_text_after_2": "# Do not edit this manually. Use Configure --openssldir=DIR do change this!",
          "line_text_after_3": "OPENSSLDIR=/usr/local/ssl",
          "line_text_before_1": "INSTALL_PREFIX=",
          "line_text_before_2": "# Normally it is left empty.",
          "line_text_before_3": "# for, say, /usr/ and yet have everything installed to /tmp/somedir/usr/.",
          "match_file_index_begin": 609,
          "match_file_index_end": 612,
          "match_line_index_begin": 22,
          "match_line_index_end": 25,
          "match_line_number": 27,
          "match_text": "ssl",
          "match_type": "protocol/SSL",
          "method": "keyword"
        },
        {
          "line_text": "# LONGCRYPT - Define to use HPUX 10.x's long password modification to crypt(3).",
          "line_text_after_1": "# DEVRANDOM - Give this the value of the 'random device' if your OS supports",
          "line_text_after_2": "#           one.  32 bytes will be read from this when the random",
          "line_text_after_3": "#           number generator is initalised.",
          "line_text_before_1": "# TERMIOS - Define the termios terminal subsystem, Silicon Graphics.",
          "line_text_before_2": "# TERMIO  - Define the termio terminal subsystem, needed if sgtty is missing.",
          "line_text_before_3": "#           system defines as well, i.e. _REENTERANT for Solaris 2.[34]",
          "match_file_index_begin": 1184,
          "match_file_index_end": 1189,
          "match_line_index_begin": 6,
          "match_line_index_end": 11,
          "match_line_number": 39,
          "match_text": "CRYPT",
          "match_type": "generic",
          "method": "keyword"
        }
      ]
    },
    "openssl-1.0.2d-r0-patched.tar.gz/openssl-1.0.2d/util/sp-diff.pl": {
      "SHA1_checksum": "d59826a6a471483298d4a9e05c5c779201823fd7",
      "matches": [
        {
          "line_text": "\t\"idea cfb\",\"idea cbc\",\"rc2 cfb\",\"rc2 cbc\",\"blowfish cbc\",\"cast cbc\")",
          "line_text_after_1": "\t{",
          "line_text_after_2": "\tif (defined($one{$a,8}) && defined($two{$a,8}))",
          "line_text_after_3": "\t\t{",
          "line_text_before_1": "foreach $a (\"md2\",\"md4\",\"md5\",\"sha\",\"sha1\",\"rc4\",\"des cfb\",\"des cbc\",\"des ede3\",",
          "line_text_before_2": "$line=0;",
          "line_text_before_3": "",
          "match_file_index_begin": 425,
          "match_file_index_end": 433,
          "match_line_index_begin": 44,
          "match_line_index_end": 52,
          "match_line_number": 15,
          "match_text": "blowfish",
          "match_type": "algorithm/symmetric/block-cipher/Blowfish",
          "method": "keyword"
        }
      ]
    }
  }
}

```
####Output fields ####
The output is organized by files in which matches were found, and for each file, SHA1 checksum is computed for integrity check.

#####line_text#####
The line of code containing the match.
#####line_text_after_<#> and line_text_before<#>#####
Surrounding lines of code around the line that contains matches. This is to provide a bit of context.
#####match_file_index_begin and match_file_index_end#####
The index in the file where match starts and ends when file is read at once.
#####match_line_index_begin and  match_line_index_end#####
The beginning and end index in the line where the match occurs.
#####match_line_number#####
The line number of the line of code where match starts.
#####match_text#####
The text of the match.
#####match_type#####
The type of this match. It is either an encryption algorithm, a library, a protocol or standard, or generic evidence for encryption.
#####method#####
The method that found this match.
#####errors#####
If an error occured during processing of this package, it will be listed here.
#####stats#####
This section provides general execution statistics, including the time it took to process files, file count, count of the lines of text, and the number of bytes processed.

##Generating reports##
The standard output of this program is the .crypto files containing JSON data. They can, however, be translated to different formats depending on the user's needs. Inside the folder `/reporting`, you'll find scripts that will read .crypto files and convert them to different formats.

###CSV report###
The file `/reporting/translate_to_csv.py` can be used to convert all crypto files in a directory to CSV format. To use it, run

```
python3 translate_to_csv.py /path/to/file1.crypto /path/to/file2.crypto /path/to/folder/*.crypto ...
```

There is only one option:

#####--output, or -o#####
Specifies the directory into which output CSV files should be written. By default, this is the current working directory.

## FAQ ##

###What happens if an error occurs during the execution?###
If the error is related to inputs being invalid, the program prints the error message and terminates. However, some errors might not be discovered during startup. For example, a file in a package may be corrupt or unreadable. In that case, an error message will be printed to standard error, the error message will be appended to the `"errors"` section of the crypto output, and the execution will continue on. A good test of knowing everything went okay in the end is to count the number of crypto files. They should be equal to the number of packages you scanned.

###How can I make it run faster by running it in parallel on a multi-core machine?###
In Unix and Unix-like systems like Ubuntu or OS X, this can be easily accomplished by installing [GNU parallel](https://www.gnu.org/software/parallel/). In Debian-based systems, it is installed via
```
sudo apt-get install parallel
```
and similarly, on OS X,
```
sudo brew install parallel
```
Unfortunately, there is no direct port of GNU parallel for Windows. But it is available in [Cygwin](https://www.cygwin.com/).

Once this tool is installed, simply create a command_list.txt containing

```
python3 scan-for-crypto.py package1
python3 scan-for-crypto.py package2
...
```
and execute
```
parallel -j [number of cores] < command_list.txt
```
This way, packages are processed in parallel, one package per core.

###How can I see the list of methods available for scanning a package?###
Simply open the help guide by running:
```
python3 scan-for-crypto.py -h
```
List of available methods will be in the help message of the `--methods` option. As of now, there are only two methods that are usable, `keyword` and `api`.


## FAQ for developers ##

###Keyword search and API finder are great, but I want to create my own way of searching code for encryption. How can I do that? ###

Start by creating a folder under `/methods` to put your files there. Have a look at our `hello_world` method under `/cryptodetector/methods/hello_world`. This provides a skeleton for writing a new method. As you can see, a method inherits from the `Method` class and must have a `method_id` attribute. Note that the name you give to your method folder, file names, and the class name for your method are arbitrary. The only thing that uniquely identifies the method is its `method_id`.

Every method class should implement the following three functions:

* `search(content, language)`
Searches the string `content` for encryption. `language` specifies the language of the content,
defined in the file `languages.py`. It returns a list of matches, where each match is dict object containing all the output fields. The example hello_world class shows basic usage.

* `quick_search(content, language)`
Returns `True` or `False` if it found one or more matches in the content in the given language.

* `supports_scanning_file(language) `
Returns `True` or `False` indicating whether this method supports scanning files in the given language.

In addition, a method class can have `options` and  `options_help` attributes, but these are not required. The hello_world example shows how to create your own options in the method. To set them from the command line, simply reference them by `--[your_method_id]-[your_option]`, replacing all underscores by dashes. For example, `example_value` option can be set from the command line by `--hello-world-example-value`. Indeed, you will see it if you run the help guide `python3 scan-for-crypto.py -h`. Have a look at the example config file `cryptodetector.conf` for the syntax of specifying method options from the config file.


### I have an idea or suggestion. How can I contribute to the project?###

We welcome your ideas and suggestions. Please create a fork of this project, make any edits to the
code that you like, push them to a branch, and create a pull request from that branch by going here:
https://github.com/Wind-River/crypto-detector/pulls. If you'd like to contact the maintainers,
please email kamyar.kaviani@windriver.com or mark.gisi@windriver.com.

## License ##

This project is subject to Wind River Commercial License. The right to copy, distribute, modify, or otherwise make use of this software may be licensed only pursuant to the terms
of an applicable Wind River license agreement.
