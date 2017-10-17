# Crypto Detector #

## Overview ##

Detecting cryptography in the source code of open-source packages or libraries turns out to be a common problem for many of the software companies that include these packages in their products.

At Wind River, we face a similar challenge. Thousands of packages are bundled as part of the Wind River operating system. We are developing this project to be an automated and efficient code parser that can determine, with some degree of confidence, that a piece of code contains restricted encryption algorithms. The output could then be verified by a human expert.


## Methods of scanning code ##

More often than not, source code that contains an encryption algorithm has words that are very related to that algorithm. For example, a block of open source code that makes use of the DES algorithm is very likely to contain strings such as "DES_" or "cipher". So as a start, we can scan the source code searching for these keywords. This is a simple, first-pass that gives us an initial idea as to whether or not the source code might contain encryption. We call this the *keyword* method.

To go one step further, we search the content of each file for API calls to encryption libraries, include files, encryption data types, and other evidence that might ascertain the use of encryption libraries or services. This is our *API finder* method.

## Encryption algorithms ##

This script crudely detects the following cryptography schemes:

* Asymmetric cryptography

 >RSA, DSA, Diffie-Hellman, ECC, ElGamal, Rabin, XTR
* Block ciphers

 >AES, DES, RC2, RC5, RC6, CAST, Blowfish, Twofish, Threefish, Rijndael, Camellia, IDEA, SEED, Serpent, SHACAL, GOST, TEA, XTEA, BTEA, SAFER, Feistel, IntelCascade, KASUMI, MISTY1, NOEKEON, SHARK, Skipjack, BEAR-LION, RFC2268, MARS, Diamond2, DFC, CSCipher
* Stream ciphers

 >RC4, Salsa20, XSalsa20, ChaCha20, PANAMA, SEAL, SOSEMANUK, WAKE
* Substitution ciphers

 >ROT13
* Hybrid encryption

 >PGP, GPG
* Hashing algorithms

 >MD2, MD4, MD5, SHA-1, SHA-2, SHA-3, MDC-2, BLAKE, HMAC, RIPEMD, HAVAL, Tiger, Whirlpool, GOST, Adler32, Streebog
* Protocols and standards

 >SSL, TLS, SSH, PKI, PKCS, MQV, kerberos, ASN1, MSCHAP
* Encryption libraries

 >OpenSSL, OpenSSH, libgcrypt, Crypto++, cryptlib, libXCrypt, libMD, glibC, BeeCrypt, Botan,
 BouncyCastle, SpongyCastle, QT, JAVA SE 7, WinCrypt
* Message Authentication Codes

 >HMAC, Poly1305

* Cryptographic random number generators

* And other generic encryption evidence

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

#### Packages ####
Space-separated list of packages to scan. A package can be given as a path to a local directory, a local file, a local compressed archive, wild-card address, a remote archive, URL to a single source file, or a GitHub link. Have a look at `cryptodetector.conf` file for list of examples.

#### Options ####
##### --config-file=`<file path>` or -c `<file path>` #####
The path to the configuration file. If a configuration file is present, all options will be read from this file first, with additional command line arguments overriding them. Next section covers the specifications of a configuration file.

##### --methods=`<comma-separated list>` or -m `<comma-separated list>` #####
Specifies the methods of scanning. Accepts a comma-separated list of methods. A method can be one of `keyword` or `api`, pertaining to the keyword search and API finder respectively.

##### --output=`<path to directory>` or -o `<path to directory>` #####
Specifies the path in which the output files should be written. If this option is not provided, the default value is the current working directory.

##### --output-in-package-directory or -p or --output-in-package-directory=`<True|False>` #####
With this option, this script will create the output file for a package in the directory in which that package resides. Note this will only work for local packages that have a directory.

##### --output-existing=`<rename|overwrite|skip>` #####
Specifies what to do when an output crypto file already exists. Can be one of three options: `rename` (default) renames the new crypto file .1.crypto, .2.crypto and so on, `overwrite` overwrites the old file, and `skip` skips scanning the package.

##### --quick or -q or --quick=`<True|False>` #####
Performs a quick/express search on a set of given packages, returning a list of only the packages that had at least one match found in any of their files. In the end, it writes the output as a list to the terminal and creates a file in the output directory called `quick-scan-result.txt`.

##### --stop-after=k or -s k #####
Specifies to stop the search during execution of each method after finding `k` files with matches in them. `k` has to be a positive integer.

##### --keyword-ignore-case or --keyword-ignore-case=`<True|False>` #####
Makes the keyword search case-insensitive.

##### --keyword-kwlist-path=`<path to a file>` #####
Path to the keyword list file for the keyword method. By default, this is `/cryptodetector/methods/keyword/keyword_list.txt`.

##### --api-kwlist-path=`<path to a file>` #####
Path to the keyword list file for the API finder method. By default, this is `/cryptodetector/methods/api/api_definitions.txt`.

##### --ignore-match-types=`<list of match types>` #####
Comma-separated list of match types to ignore while searching files for matches.

##### --source-files-only or --source-files-only=`<True|False>` #####
Specifies whether or not to scan only the files that are source code files (for example .cpp files, .py files, etc) The type of a file is guessed based on its extension (mime type).

##### --pretty or --pretty=`<True|False>` #####
Places indentation and additional spaces in the output crypto files to make them more readable (pretty) at the cost of producing larger files.

##### --verbose or -v or --verbose=`<True|False>` #####
Specifies whether to verbosely processes files and print out information.

##### --suppress-warnings or -W or --suppress-warnings=`<True|False>` #####
Specifies not to write warning messages.

##### --version #####
Shows the version of this program.

##### --help or -h #####
Shows a help guide.

#### Configuration File ####
A configuration file contains all the options to the program, so one doesn't have to type them out in the command line every time. The path to the configuration file could be specified by the option `--config-file` or `-c` as specified above.

If this option is not present, this program will look for the file `cryptodetector.conf` in the *current working directory*. This is the directory in which the command line interpreter works, not necessarily the directory where this script is saved.

If the configuration file is not found there, it looks for it in the home folder. In Unix and Unix-like systems, this is the directory referred to as `~/`. In Windows, this is the `%UserProfile%` directory. Depending on the version of Windows, that could be one of `<drive>:\Documents and Settings\<user>` or ` <drive>:\Users\<user>` .

If no config file is found, the program expects all the parameters from the command line.

Look at the example file `cryptodetector.conf` for the syntax. It is the same syntax as most other configuration files, where sections are enclosed by brackets and items are under sections, line by line. If an item has a value, its value is provided by the equal sign. Commenting out a line is simply putting a ` #` sign in front of it.

#### Examples ####

To scan a single package (with default keyword search)

```
python3 scan-for-crypto.py /path/to/root/of/package
```

To scan two packages with keyword search and API finder

```
python3 scan-for-crypto.py --methods=keyword,api /path/to/package1 /path/to/package2
```

To download, extract, and scan the content of an archive using the API method, stopping the search after finding matches in at most 4 files

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
This script creates a set of `<package>.crypto` files for each package that it scans. It writes a JSON object in this file. For specification of the output format, see [output specification](/crypto-output-specification/crypto-spec-2.0.md).

## FAQ ##

### What happens if an error occurs during the execution? ###
If the error is related to inputs being invalid, the program prints the error message and terminates. Run-time errors are printed to standard error and added to the `"errors"` section of the crypto output, but they do not stop the execution of the program, unless it is an unhandled exception. A good test of knowing everything went okay in the end is to count the number of crypto files. They should be equal to the number of packages you scanned. You can check the log files to see if there was any run-time error.

### How can I make it run faster by running it in parallel on a multi-core machine? ###
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

### How can I see the list of methods available for scanning a package? ###
Simply open the help guide by running:
```
python3 scan-for-crypto.py -h
```
List of available methods will be in the help message of the `--methods` option. As of now, there are only two methods that are usable, `keyword` and `api`.


## FAQ for developers ##

### Keyword search and API finder are great, but I want to create my own way of searching code for encryption. How can I do that? ###

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


### I have an idea or suggestion. How can I contribute to the project? ###

We welcome your ideas and suggestions. Please create a fork of this project, make any edits to the
code that you like, push them to a branch, and create a pull request from that branch by going here:
https://github.com/Wind-River/crypto-detector/pulls. If you'd like to contact the maintainers,
please email kamyar.kaviani@windriver.com or mark.gisi@windriver.com.

## Project License ##

Crypto Detector is free and distributed under the **Apache License, Version 2.0**. For further details, visit http://www.apache.org/licenses/LICENSE-2.0. Text for the crypto-detector and other applicable license notices can be found in the LICENSE file in the project top level directory. Different files may be under different licenses. Each source file should include a license notice that designates the licensing terms for the respective file.

## Legal Notices ##

Disclaimer of Warranty / No Support: Wind River does not provide support and maintenance services for this software, under Wind River’s standard Software Support and Maintenance Agreement or otherwise. Unless required by applicable law, Wind River provides the software (and each contributor provides its contribution) on an “AS IS” BASIS, WITHOUT WARRANTIES OF ANY KIND, either express or implied, including, without limitation, any warranties of TITLE, NONINFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the appropriateness of using or redistributing the software and assume any risks associated with your exercise of permissions under the license.
