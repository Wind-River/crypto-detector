# Crypto JSON Output Specification Version 2.0 #

```
{
    "crypto_spec_version": <float>,

    "file_collection_verification_code": <string>,

    "package_name": <string>,

    "crypto_evidence": [

        <file sha1>: {

            "file_paths": [<array of strings>],

            "hits": [

                {

                    "evidence_type": <string>,

                    "detection_method": <string>,

                    "encryption_api_usage": <string>,

                    "encryption_library": <string>,

                    "matched_text": <string>,

                    "line_number": <integer>,

                    "line_index_begin": <integer>,

                    "line_index_end": <integer>,

                    "file_index_begin": <integer>,

                    "file_index_end": <integer>,

                    "line_text": <string>,

                    "line_text_after_1": <string>,

                    "line_text_after_2": <string>,

                    "line_text_after_3": <string>,

                    "line_text_before_1": <string>,

                    "line_text_before_2": <string>,

                    "line_text_before_3": <string>,

                    "comments": <string>,

                    "human_reviewed": <string>
                },

                ...

            ]
        },

        ...
    ]
}

```

## crypto_spec_version ##
The version of the crypto specification.

## package_name ##
The name of the package that was scanned.

## file_collection_verification_code ##
A SHA1 signature to uniquely identify the set of files in this package. To compute it, we collect the SHA1 of every file in the leaves of the directory tree, skipping symbolic links, sort this list in ascending alphabetical order, concatenate them into single string, and take SHA1 of the resulting string.

## crypto_evidence ##
The report of evidence found in the package.

### file_paths ###
Array of file paths that all have this file SHA1. Note that multiple files in the same package can have identical content, so they are grouped in this way.

### hits ###
Array of dictionary objects for each hit.

#### evidence_type ####
Categorization of the type of evidence found.

#### encryption_api_usage ####
Type of the encryption API usage: one of "call", "data_type", or "include". "call" is call to an exported function, "data_type" is instantiating a data structure that belongs to a cryptography library, and "include" is including header files or otherwise importing files that faciliate encryption.

#### encryption_library ####
The library or service that provided the API.

#### matched_text ####
The exact text of the match.

#### line_number ####
The line number of the matching line.

#### line_index_begin ####
The index within the line where the match begins.

#### line_index_end ####
The index within the line where the match ends.

#### file_index_begin ####
The index within the whole file starting from its beginning where the match begins.

#### file_index_end ####
The index within the whole file starting from its beginning where the match ends.

#### line_text ####
The line of code that was matched.

#### line_text_before\_\# ####
The surrounding lines of code before the matching line.

#### line_text_after\_\# ####
The surrounding lines of code after the matching line.

#### comments ####
Field for adding comments.

#### human_reviewed ####
Reserved for communicating the result of a human review of this hit.
