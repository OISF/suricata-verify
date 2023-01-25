#! /usr/bin/env python3
#
# Check JSON objects for duplicate keys.
#
# NOTE: This will only report the first duplicate key found in a line
# of JSON. More duplicates may be found after fixing the first.

import json
import sys

class DuplicateKeyError(Exception):
    pass

def validate_file(filename):
    with open(filename) as json_in:
        for line in json_in:
            json.loads(line, object_pairs_hook=hook)

def main():
    failures = 0
    for filename in sys.argv[1:]:
        try:
            validate_file(filename)
        except DuplicateKeyError as err:
            print("ERROR: Duplicate key: {}: {}".format(filename, err))
        except Exception as err:
            print("ERROR: Unknown: {}: {}".format(filename, err))
            failures += 1

    return failures

def hook(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            equal = d[k] == v
            raise DuplicateKeyError("key={}, equal={} current value={}, new value={}".format(k, equal, d[k], v))
        d[k] = v
    return d

if __name__ == "__main__":
    sys.exit(main())
