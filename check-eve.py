#! /usr/bin/env python3

import sys
import os
import os.path
import argparse
import json
from jsonschema import validate
from jsonschema.exceptions import ValidationError

def validate_json(json_filename, schema):
    objList = []

    with open(json_filename) as f:
        for line in f:
            jsonObj = json.loads(line)
            objList.append(jsonObj)

        for obj in objList:
            try:
                validate(instance = obj, schema=schema)
            except ValidationError as err:
                print(err.message) 
        
def main():
    global args

    parser = argparse.ArgumentParser(description="Validation schema")
    args = parser.parse_args()
    TOPDIR = os.path.abspath(os.path.dirname(sys.argv[0]))
    tdir = os.path.join(TOPDIR, "tests")

    schema = json.load(open("schema.json"))

    # # Validate output-eve-fileinfo/expected/eve.json
    # jsonfile = os.path.join(tdir,"output-eve-fileinfo/output/eve.json")
    # validate_json(jsonfile, schema)

    # os.walk the test directory for eve.json files and validate each one
    for dirpath, dirnames, filenames in os.walk(tdir):
        
        if 'eve.json' in filenames and os.path.basename(dirpath) == "output":
            json_filename = os.path.join(dirpath, 'eve.json')
            print(json_filename, "===>")

            validate_json(json_filename, schema)
        print()

if __name__ == "__main__":
    sys.exit(main())
