#! /usr/bin/env python3
#
# Copyright (C) 2021 Open Information Security Foundation
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import os
import os.path
import argparse
import json
from jsonschema import validate
from jsonschema.exceptions import ValidationError

def validate_json(args, dirpath, schema, isDirectory):
    json_filename = dirpath
    if isDirectory:
        json_filename = os.path.join(dirpath, 'eve.json')
        
    testname = dirpath
    if "suricata-verify" in dirpath:
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
    parser.add_argument("file", nargs="?", default=[])
    args = parser.parse_args()
    TOPDIR = os.path.abspath(os.path.dirname(sys.argv[0]))
    tdir = os.path.join(TOPDIR, "tests")

    # ../suricata-verify/schema.json 
    schema = json.load(open("schema.json"))

    checked = 0
    passed = 0
    failed = 0

    isDirectory = True
    argfile = args.file

    if argfile:
        # if the argument is a single file
        if os.path.isfile(argfile):
            isDirectory = False
            status = validate_json(args, argfile, schema, isDirectory)
            checked += 1
            if status == "OK":
                passed += 1
            else:
                failed += 1

        # if the argument is a directory
        elif os.path.isdir(argfile):
            tdir = argfile
           
    if isDirectory:
        # os.walk for eve.json files and validate each one
        for dirpath, dirnames, filenames in os.walk(tdir):
            if 'eve.json' in filenames:
                status = validate_json(args, dirpath, schema, isDirectory)
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
