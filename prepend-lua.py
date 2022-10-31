#! /usr/bin/env python3

import os

start_dir = "tests/"
for root, dirs, files in os.walk(start_dir):
    for file in files:
        if file.endswith("lua"):
            print(os.path.join(root, file))
            script_path = os.path.join(root, file)
            with open(script_path, "r") as original: data = original.read()
            with open(script_path, 'w') as modified: modified.write("local io = require(\"io\")\n" + data)
