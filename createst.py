#! /bin/python
#
# Copyright (C) 2019-2022 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

import argparse
import glob
import json
import logging
import os
import subprocess
import sys
from collections import defaultdict
from shutil import copyfile

import yaml
from yaml.representer import Representer

# Get a logger instance
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Define YAML representer
yaml.add_representer(defaultdict, Representer.represent_dict)

WIN32 = sys.platform == "win32"
suricata_bin = "src\suricata.exe" if WIN32 else "./src/suricata"
suricata_yaml = "suricata.yaml" if WIN32 else "./suricata.yaml"
CUR_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_TEST_DIR = os.path.join(CUR_DIR, "tests")

# Fields to exclude from the filter block
skip_fields = ["timestamp", "flow_id", "last_reload"]


def init_logger():
    """
    Initialize logger handler and format.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def init_global_params():
    """
    Initialize global parameters before getting into major functions.
    """
    global args
    global test_dir
    global cwd
    args = vars(parse_args())
    test_dir = os.path.join(args["output_path"], args["test-name"])
    # Get current working directory. This should be a valid Suricata source directory.
    cwd = os.getcwd()


def modify_eve_dict(eve_dict):
    """
    Modify nested event dictionary to make it follow a more flattened
    approach so as to use full functionality of the run.py function
    `find_value(name, obj)`. The dictionaries of the format
    {
        "event_type":"http",
        "http":{
            "hostname":"supportingfunctions.us.newsweaver.com",
            "http_port":443
            }
    }

    will be converted to

    {
        "event_type":"http",
        "http.hostname":"supportingfunctions.us.newsweaver.com",
        "http.http_port":443
    }
    """
    modified = {}

    def flatten(x, name=''):
        """
        Recursive function to flatten the nested dictionaries.
        """
        if type(x) is dict:
            for val in x:
                flatten(x[val], name + val + '.')
        elif type(x) is list:
            i = 0
            for val in x:
                name = name.rstrip('.')
                flatten(val, name + '[' + str(i) + ']' + '.')
                i += 1
        else:
            if name[:-1] not in ["flow.start", "flow.end"]:
                modified[name[:-1]] = x

    flatten(eve_dict)
    return modified


def create_directory(path):
    """
    Helper function to create output directories.
    """
    dir_path = os.path.join(args["output_path"], path)
    try:
        os.mkdir(dir_path)
    except OSError as e:
        logger.error(e)
        sys.exit(1)


def write_to_file(data):
    """
    Check for the output test.yaml file if it exists, else create one and write
    to it.
    """
    test_yaml_path = os.path.join(test_dir, "test.yaml")
    try:
        os.remove(test_yaml_path)
    except FileNotFoundError:
        logger.info("{} not found. Creating...".format(test_yaml_path))
    except IsADirectoryError as e:
        logger.error(e)
        sys.exit(1)
    with open(test_yaml_path, "w+") as fp:
        fp.write("# *** Add configuration here ***\n\n")
        if check_requires():
            fp.write("requires:\n")
        if args["min_version"]:
            fp.write("   min-version: %s\n\n" % args["min_version"])
        if check_set_args():
            fp.write("args:\n")
            if not args["strictcsums"]:
                fp.write("- -k none\n")
            if args["midstream"]:
                fp.write("- --set stream.midstream=true\n")
            fp.write("\n")
        fp.write(data)

def check_requires():
    features = ["min_version"]
    for item in features:
        if args[item]:
            return True

def check_set_args():
    """
    Check if the user wants midstream set to true and/or to have strict
    checksums
    """
    user_args = ["strictcsums", "midstream"]
    no_user_args = True
    for item in user_args:
        if args[item]:
            if item != "strictcsums":
                return True
            no_user_args = False
        elif no_user_args:
            return True

def test_yaml_format(func):
    """
    Decorator to convert all events to test.yaml format.
    """
    def decorated(*args, **kwargs):
        """
        Add filters per event in eve.json.
        """
        eve_list = func(kwargs["eve_ds"])
        all_eve_list = []
        for item in eve_list:
            eve_dict = {
                    "filter": {
                        "count": item[1],
                        "match": modify_eve_dict(item[0]),
                        },
                    }
            all_eve_list.append(eve_dict)
        all_eve_dict = {"checks": all_eve_list}
        all_eve_yaml = yaml.dump(all_eve_dict, default_flow_style=False)
        return all_eve_yaml
    return decorated


def is_valid_suri_directory():
    """
    Check if the current working directory is a valid Suricata source
    directory by checking presence of suricata.yaml and `src/suricata`.
    """
    if not (os.path.exists(suricata_yaml) and
            os.path.exists(suricata_bin)):
        logger.error("This is not a Suricata source directory or " +
              "Suricata is not built")
        return False
    return True


def get_manipulated_list():
    """
    Manipulate eve.json to load json successfully and skip the fields
    mentioned in `skip_fields` variable.
    """
    eve_path = os.path.join(test_dir, "output", "eve.json")
    allow_events = args["allow_events"].strip().split(",") if args["allow_events"] else []
    with open(eve_path, "r") as fp:
        content = fp.read()
    content_list = content.strip().split("\n")
    jcontent_list = [json.loads(e) for e in content_list]
    all_content_list = []
    for e in jcontent_list:
        md = {k: v for k, v in e.items() if k not in skip_fields}
        if "event_type" in md and md["event_type"] == "stats":
            continue
        all_content_list.append(md)
    if allow_events:
        def_eve_content_list = [item for item in all_content_list if item["event_type"] in allow_events]
        if not def_eve_content_list:
            logger.error("No matching events found.")
            sys.exit(0)
        return def_eve_content_list
    return all_content_list


def filter_event_type_params(eve_rules):
    """
    Create a filter block based on *ALL* the parameters of any event.
    """
    mlist = get_manipulated_list()
    all_eve_list = get_all_eve_list(eve_ds=mlist)
    write_to_file(data=all_eve_list)


def filter_event_type(event_types):
    """
    Filter based *ONLY* on the event types.
    """
    all_eve_list = get_eve_list_by_type(eve_ds=event_types)
    write_to_file(data=all_eve_list)


@test_yaml_format
def get_eve_list_by_type(eve_ds):
    eve_list = []
    for k, v in eve_ds.items():
        key = {"event_type": k}
        eve_list.append((key, v))
    return eve_list


@test_yaml_format
def get_all_eve_list(eve_ds):
    eve_list = []
    for item in eve_ds:
        eve_list.append((item, 1))
    return eve_list


def get_suricata_yaml_path():
    """
    Return the path to the suricata.yaml particular to the current test.
    """
    if os.path.exists(os.path.join(cwd, "suricata.yaml")):
        return os.path.join(cwd, "suricata.yaml")
    return os.path.join(test_dir, "suricata.yaml")


def create_local_args():
    """
    Return a list of all the arguments required to be passed to a particular
    local test.
    """
    test_output_dir = os.path.join(test_dir, "output")
    pcap_path = os.path.join(test_dir, "input.pcap")
    # Copy PCAP to the test directory
    copyfile(args["pcap"], pcap_path)

    largs = [
        os.path.join(cwd, "src/suricata"),
        '-r', pcap_path,
        '-l', test_output_dir,
        "--init-errors-fatal",
        "-c", get_suricata_yaml_path(),
        ]
    # In Suricata 5.0 the classification.config and
    # reference.config were moved into the etc/ directory. For now
    # check there and the top level directory to still support
    # 4.1.
    classification_configs = [
        os.path.join(cwd, "etc", "classification.config"),
        os.path.join(cwd, "classification.config"),
    ]

    for config in classification_configs:
        if os.path.exists(config):
            largs += ["--set", "classification-file=%s" % config]
            break

    reference_configs = [
        os.path.join(cwd, "etc", "reference.config"),
        os.path.join(cwd, "reference.config"),
    ]

    for config in reference_configs:
        if os.path.exists(config):
            largs += ["--set", "reference-config-file=%s" % config]
            break

    # Check if rules were provided with args
    if args["rules"]:
        rules_path = os.path.join(test_dir, "test.rules")
        copyfile(args["rules"], rules_path)
        largs += ["-S", rules_path]
    else:
        largs.append("--disable-detection")

    return largs


def create_env():
    """
    Return environment for the test being created.
    """
    test_output_dir = os.path.join(test_dir, "output")
    extraenv = {
        # The suricata source directory.
        "SRCDIR": cwd,
        "TZ": "UTC",
        "output_dir": test_output_dir,
        "ASAN_OPTIONS": "detect_leaks=0",
    }
    env = os.environ.copy()
    env.update(extraenv)

    return env


## Parser
def parse_args():
    """
    Parse arguments and return them to main for processing.
    """
    parser = argparse.ArgumentParser(
        description="Create tests with a given PCAP. Execute the script"
                " from a valid Suricata source directory.")
    parser.add_argument("test-name", metavar="<test-name>",
                        help="Name of the test folder")
    parser.add_argument("pcap", metavar="<pcap-file>",
                        help="Path to the PCAP file")
    parser.add_argument("--rules", metavar="<rules>",
                        help="Path to rule file")
    parser.add_argument("--output-path", default=DEFAULT_TEST_DIR, metavar="<output-path>",
                        help="Path to the folder where generated test.yaml should be put")
    parser.add_argument("--eventtype-only", default=None, action="store_true",
                        help="Create filter blocks based on event types only")
    parser.add_argument("--allow-events", nargs="?", default=None,
                        help="Create filter blocks for the specified events")
    parser.add_argument("--strictcsums", default=None, action="store_true",
                        help="Strictly validate checksum")
    parser.add_argument("--midstream", default=False, action="store_true",
                        help="Allow midstream session pickups")
    parser.add_argument("--min-version", default=None, metavar="<min-version>",
                        help="Adds a global minimum required version")

    # add arg to allow stdout only
    args = parser.parse_args()

    return args


def eve2test():
    """
    Process the provided eve.json file and write the required checks in the
    provided output file.
    """
    logger.info("Running eve2test...")
    content = list()
    event_types = defaultdict(int)
    eve_path = os.path.join(test_dir, "output", "eve.json")
    with open(eve_path, "r") as fp:
        for line in fp:
            eve_rule = json.loads(line)
            content.append(eve_rule)
            eve_type = eve_rule.get("event_type")
            event_types[eve_type] += 1
    if args["eventtype_only"]:
        if args["allow_events"]:
            logger.warning("--allow-events shall not be used with --eventtype-only")
        filter_event_type(event_types=event_types)
        return
    filter_event_type_params(eve_rules=content)


def generate_eve():
    """
    Create eve.json with Suricata as per the given configuration and PCAP.
    In case of successful run, call eve2test to convert eve.json thus
    created into test.yaml.
    """
    largs = create_local_args()
    env = create_env()

    if not args["strictcsums"]:
        largs += ["-k", "none"]
    if args["midstream"]:
        largs += ["--set", "stream.midstream=true"]
    p = subprocess.Popen(
        largs, cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = p.communicate()
    exit_status = p.wait()
    if exit_status == 0:
        eve2test()
    else:
        logger.error(stderr.decode("utf-8"))
        sys.exit(1)


def main():
    init_logger()

    # Check if its a valid Suricata directory
    if not is_valid_suri_directory():
        sys.exit(1)

    init_global_params()
    create_directory(path=args["test-name"])
    create_directory(path=os.path.join(args["test-name"], "output"))
    generate_eve()


if __name__ == "__main__":
    main()
