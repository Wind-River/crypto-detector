#!/usr/bin/python3

"""
Copyright (c) 2017 Wind River Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.


Utility to translate .crypto files to CSV format
"""
import argparse
import json
import os
import csv

class CryptoReadError(Exception): pass

def process_files():
    try:
        parser = argparse.ArgumentParser(
            description="Utility to translate .crypto reports to CSV format")

        parser.add_argument("-o", "--output", \
           dest="output", default=os.getcwd(), \
           help="The output directory")

        parser.add_argument("crypto_files", nargs='+')

        parsed_args = vars(parser.parse_args())
        output_directory = parsed_args["output"]

        for crypto_file_path in parsed_args["crypto_files"]:
            if os.path.islink(crypto_file_path):
                print("Warning: " + crypto_file_path + " is a symbolic link.")
                continue

            extension = crypto_file_path.split(".")[-1]
            if extension != "crypto":
                continue

            filename = os.path.basename(crypto_file_path)

            print("Processing " + filename + " ...")

            try:
                with open(crypto_file_path, 'r') as crypto_file:
                    crypto_data = json.loads(crypto_file.read())
            except:
                raise CryptoReadError()

            if "crypto_evidence" not in crypto_data:
                print("Invalid crypto file: " + crypto_file_path \
                    + ". Missing 'crypto_evidence' field ")
                continue

            csv_filename = os.path.join(output_directory, filename + ".csv")

            try:
                with open(csv_filename, 'w') as file:
                    writer = csv.writer(file)

                    writer.writerow(["File Paths", "Evidence Type", "Detection Method", "Match", \
                        "Line Number", "Source Matched", "Index Begin", "Index End"])

                    for file_sha1 in crypto_data["crypto_evidence"]:
                        for hit in crypto_data["crypto_evidence"][file_sha1]["hits"]:

                            line_number = hit["line_number"]
                            source = ""
                            surrounding_lines = {
                                -3: hit["line_text_before_3"],
                                -2: hit["line_text_before_2"],
                                -1: hit["line_text_before_1"],
                                0: hit["line_text"],
                                1: hit["line_text_after_1"],
                                2: hit["line_text_after_2"],
                                3: hit["line_text_after_3"]
                                }

                            for i in range(-3, 4):
                                if line_number + i < 0:
                                    continue

                                if i == 0:
                                    line_number_text = "[" + str(line_number + i) + "]: "
                                else:
                                    line_number_text = str(line_number + i) + ": "

                                source += line_number_text + surrounding_lines[i] + "\n"

                            file_paths = "\n".join(crypto_data["crypto_evidence"][file_sha1]["file_paths"])

                            writer.writerow([
                                file_paths,
                                hit["evidence_type"],
                                hit["detection_method"],
                                hit["matched_text"],
                                hit["line_number"],
                                source,
                                hit["line_index_begin"],
                                hit["line_index_end"]])
            except:
                if os.path.isfile(csv_filename):
                    os.remove(csv_filename)
                raise

            print("done")

    except CryptoReadError:
        print("Failed to open the crypto file and parse its JSON content.")

    except Exception as error:
        print("Encountered an error while processing the CSV file.\n\n")
        raise

if __name__ == '__main__':
    process_files()
