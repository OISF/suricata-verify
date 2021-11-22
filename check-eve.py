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
import subprocess
from jsonschema import validate
from jsonschema.exceptions import ValidationError

def validate_json(args, dirpath, schema, isDirectory, json_path):
    json_filename = dirpath
    if isDirectory:
        json_filename = os.path.join(dirpath, 'eve.json')
        
    status = "OK"
    errors = []

    if args.rust:
        cp = subprocess.run(["jsonschema-rs-iter", json_path, "-i", json_filename], capture_output=True)
        if cp.returncode != 0:
            status = "FAIL"
            errors.append(cp.stdout)
    else:
        with open(json_filename) as f:
            for line in f:
                obj = json.loads(line)
                try:
                    validate(instance = obj, schema=schema)
                except ValidationError as err:
                    status = "FAIL"
                    errors.append(err.message)
    
    if not args.quiet:
        if status == "FAIL":
            print("===> %s: FAIL " % json_filename)

            for err in errors:
                print(err)
        elif args.verbose:
            print("===> %s: OK " % json_filename)

    return status
        
def main():
    global args

    parser = argparse.ArgumentParser(description="Validation schema")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("-r", dest="rust", action="store_true")
    parser.add_argument("file", nargs="?", default=[])
    parser.add_argument("-q", dest="quiet", action="store_true")
    args = parser.parse_args()
    TOPDIR = os.path.abspath(os.path.dirname(sys.argv[0]))
    tdir = os.path.join(TOPDIR, "tests")

    json_path = "{}/schema.json".format(TOPDIR)
    schema = json.load(open(json_path))

    checked = 0
    passed = 0
    failed = 0

    isDirectory = True
    argfile = args.file
    
    if argfile:
        # if the argument is a single file
        if os.path.isfile(argfile):
            isDirectory = False
            status = validate_json(args, argfile, schema, isDirectory, json_path)
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
                status = validate_json(args, dirpath, schema, isDirectory, json_path)
                checked += 1
                if status == "OK":
                    passed += 1
                else:
                    failed += 1

    if not args.quiet:
        print("CHECKED: %d" % (checked))
        print("PASSED:  %d" % (passed))
        print("FAILED:  %d" % (failed))

    if failed > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
