#! /usr/bin/env python3

import sys
import os
import os.path
import argparse
import json
from jsonschema import validate
from jsonschema.exceptions import ValidationError

def validate_json(args, dirpath, schema):
    json_filename = os.path.join(dirpath, 'eve.json')
    testname = os.path.basename(os.path.dirname(dirpath))

    status = "OK"
    errors = []

    with open(json_filename) as f:
        for line in f:
            obj = json.loads(line)
            try:
                validate(instance = obj, schema=schema)
            except ValidationError as err:
                status = "FAIL"
                errors.append(err.message)
    
    if status == "FAIL":
        print("===> %s: FAIL " % testname)
        for err in errors:
            print(err)
    elif args.verbose:
        print("===> %s: OK " % testname)

    return status
        
def main():
    global args

    parser = argparse.ArgumentParser(description="Validation schema")
    parser.add_argument("-v", dest="verbose", action="store_true")
    args = parser.parse_args()
    TOPDIR = os.path.abspath(os.path.dirname(sys.argv[0]))
    tdir = os.path.join(TOPDIR, "tests")

    schema = json.load(open("schema.json"))

    checked = 0
    passed = 0
    failed = 0

    # os.walk the test directory for eve.json files and validate each one
    for dirpath, dirnames, filenames in os.walk(tdir):
        if 'eve.json' in filenames and os.path.basename(dirpath) == "output": 
            status = validate_json(args, dirpath, schema)
            checked += 1
            if status == "OK":
                passed += 1
            else:
                failed += 1

    print("CHECKED: %d" % (checked))
    print("PASSED:  %d" % (passed))
    print("FAILED:  %d" % (failed))
    
if __name__ == "__main__":
    sys.exit(main())
