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

def read_crypto_file(path):
    """
    Read a crypto file and return its content

    Args:
        path: (string) path to the crypto file

    Returns:
        (dict) parsed JSON data as a dictionary
    """
    try:
        with open(path, 'r') as file_object:
            content = file_object.read()
            data = json.loads(content)

        return data

    except (OSError, IOError) as expn:
        print("Critical error while reading file " + path + "\n" + str(expn))

def write_data_to_csv(data, path):
    """
    Write the crypto data to a csv file

    Args:
        data: (dict)
        path: (string) where to write the crypto file

    Returns:
        None
    """
    try:
        with open(path, 'w') as file:
            writer = csv.writer(file)

            if "report" not in data:
                print("Invalid crypto file: " + path)
                return

            writer.writerow(["File Path", "Algorithm", "Method", "Match", "Line Number", \
                "Source Matched", "Index Begin", "Index End"])

            for relative_path in data["report"]:
                for match in data["report"][relative_path]["matches"]:

                    line_number = match["match_line_number"]
                    source = ""
                    surrounding_lines = {
                        -3: match["line_text_before_3"],
                        -2: match["line_text_before_2"],
                        -1: match["line_text_before_1"],
                        0: match["line_text"],
                        1: match["line_text_after_1"],
                        2: match["line_text_after_2"],
                        3: match["line_text_after_3"]
                        }

                    for i in range(-3, 4):
                        if line_number + i < 0:
                            continue

                        if i == 0:
                            line_number_text = "[" + str(line_number + i) + "]: "
                        else:
                            line_number_text = str(line_number + i) + ": "

                        source += line_number_text + surrounding_lines[i] + "\n"

                    writer.writerow([relative_path, match["match_type"], match["method"], \
                        match["match_text"], match["match_line_number"], source, \
                        match["match_line_index_begin"], match["match_line_index_end"]])

    except (OSError, IOError) as expn:
        print("Critical error while creating CSV file " + path + "\n" + str(expn))

def process_files():
    """
    Read all inputs and process crypto files

    Args:
        None

    Returns:
        None
    """
    parser = argparse.ArgumentParser(
        description="Utility to translate .crypto reports to CSV format")

    parser.add_argument("-o", "--output", \
       dest="output", default=os.getcwd(), \
       help="The output directory")

    parser.add_argument("crypto_files", nargs='+')

    parsed_args = vars(parser.parse_args())

    for path in parsed_args["crypto_files"]:
        if os.path.islink(path):
            print("Warning: " + path + " is a symbolic link.")
            continue

        extension = path.split(".")[-1]
        if extension != "crypto":
            continue

        filename = path.split("/")[-1]

        print("Processing " + filename + " ...")

        data = read_crypto_file(path)

        if not data:
            continue

        write_data_to_csv(data, os.path.abspath(os.path.join(parsed_args["output"], filename \
            + ".csv")))

if __name__ == '__main__':
    process_files()
    print("done")
