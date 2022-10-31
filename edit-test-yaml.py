#! /usr/bin/env python3

import yaml
from contextlib import redirect_stdout
import os


def output_yaml(dst_file, yaml_to_output):
    with open(dst_file, 'w') as fp:
        with redirect_stdout(fp):
            print(yaml.dump(yaml_to_output))


start_dir = "tests/"
c = 0
s = 0
for root, dirs, files in os.walk(start_dir):
    for file in files:
        if file == "test.yaml":
            small_yaml_file = os.path.join(root, file)
            small_yaml = yaml.safe_load(open(small_yaml_file))
            if "command" in small_yaml.keys():
                print(os.path.join(root, file))
                print(small_yaml["command"])
                new_command = small_yaml["command"].strip() + " --verify"
                print(new_command)
                small_yaml["command"] = new_command
                output_yaml(small_yaml_file, small_yaml)
                c += 1

print("Finished. Edited %d files." %c)
print("Newline in %d commands" %s)