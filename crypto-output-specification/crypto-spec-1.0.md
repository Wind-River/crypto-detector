# Crypto JSON Output Specification Version 1.0 #

```
{
    "package_name": <string>,

    "crypto_detector_version": <float>,

    "crypto_output_spec_version": <float>,

    "errors": <array of strings>,

    "stats": {

        "bytes_of_binary_processed": <integer>,

        "bytes_of_text_processed": <integer>,

        "execution_time": <float>,

        "file_count": <integer>,

        "lines_of_text_processed": <integer>
    }

    "scan_settings": {

        "ignore_match_types": <array of strings>,

        "log": <boolean>,

        "output_existing": <"rename"|"overwrite"|"skip">,

        "source_files_only": <boolean>,

        "stop_after": <integer|null>

        "methods": {

            "api": {

                "active": <boolean>,

                "keyword_list_version": <string>
            },

            "keyword": {

                "active": <boolean>,

                "ignore_case": <boolean>,

                "keyword_list_version": <string>
            }
        },
    },

    "report": {

        <file path>: {

            "SHA1_checksum": <string>,

            "matches": [

                {
                    "comments": <string>,

                    "human_reviewed": <string>,

                    "line_text": <string>,

                    "line_text_after_1": <string>,

                    "line_text_after_2": <string>,

                    "line_text_after_3": <string>,

                    "line_text_before_1": <string>,

                    "line_text_before_2": <string>,

                    "line_text_before_3": <string>,

                    "match_file_index_begin": <integer>,

                    "match_file_index_end": <integer>,

                    "match_line_index_begin": <integer>,

                    "match_line_index_end": <integer>,

                    "match_line_number": <integer>,

                    "match_text": <string>,

                    "match_type": <string>,

                    "method": <string>,


                    // API method only!
                    "encryption_api_usage": <string>,

                    // API method only!
                    "encryption_library": <string>

                },

                ...

            ]
        },

        ...

    }
}

```


#### package_name ####
The name of the package that was scanned.

#### crypto_detector_version ####
The version of the main script that produced this file.

#### crypto_output_spec_version ####
The version of the output specification.

#### errors ####
An array of run-time error messages that occured during scanning of this package.

## stats ##
provides general execution statistics about the run.

##### bytes_of_binary_processed #####
Total number of bytes in all the binary files that were scanned in this package.

##### bytes_of_text_processed #####
Total number of bytes in all the text files that were scanned in this package.

##### execution_time #####
Execution time for scanning this package, not including the time it took to extract archives or the time it took to clean up temporary folders.

##### file_count #####
Number of files in this package.

##### lines_of_text_processed #####
Total number of lines in all the text files that were scanned.

## scan_settings ##
The settings of the script when the job started.

##### ignore_match_types #####
List of match types that were ignored and ommitted from detection.

##### log #####
Whether or not log files were produced.

##### output_existing #####
How the script handled existing output files. Could be one of three options: 'rename' (default), 'overwrite', and 'skip'. 'rename' means new crypto file was created with .#.crypto, 'overwrite' mean older crypto files were overwritten, and 'skip' means if the file already existed, this package would have not been scanned, so it must have not existed.

##### source_files_only #####
Whether or not only source code files were scanned, and not all text files.

##### stop_after #####
Whether search was stopped after finding this many files in this package. If not set, this will be null.

##### methods #####
Settings for each of the methods.

###### active ######
Is True if the method was used to scan this package.

###### ignore_case ######
If search was carried on case-insensitive.

###### keyword_list_version ######
The version of the keyword list that was used to scan this package.

## report ##
This is the main report of all the matches. It is a key-value dictionary where a key is a file path and its value is another object with SHA1_checksum of the this file and an array of matches found in this file.

### match fields ###

##### comments #####
For adding comments later on.

##### human_reviewed #####
Field for the result of human review of this match.

##### line_text #####
The line of code that contained this match.

##### line_text_after\_\# #####
The surrounding lines of code after the matching line.

##### line_text_before\_\# #####
The surrounding lines of code before the matching line.

##### match_file_index_begin #####
The index within the file where the match begins.

##### match_file_index_end #####
The index within the file where the match ends.

##### match_line_index_begin #####
The index within the line where the match begins.

##### match_line_index_end #####
The index within the line where the match ends.

##### match_line_number #####
The line number of the matching line.

##### match_text #####
The text of the match.

##### match_type #####
The type of the match.

##### method #####
The method that found this match.


**Note**: The API finder method produces two additional fields:

##### encryption_api_usage #####
The type of the API usage, one of "call", "data_type", or "include".

##### encryption_library #####
The library that provided the API.