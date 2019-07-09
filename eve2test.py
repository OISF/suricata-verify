# Copyright (C) 2019 Open Information Security Foundation
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
import json
import logging
import os
import sys
from collections import defaultdict

import yaml
from yaml.representer import Representer

# Get a logger instance
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Fields to exclude from the filter block
skip_fields = ["timestamp", "flow_id", "last_reload"]

yaml.add_representer(defaultdict, Representer.represent_dict)


def init_logger():
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def parse_args():
    """
    Parse arguments and return them to main for processing.
    """
    parser = argparse.ArgumentParser(
        description="Convert eve.json to test.yaml")
    parser.add_argument("path-to-eve", metavar="<path-to-eve>",
                        help="Path to eve.json")
    parser.add_argument("output-path", metavar="<output-path>",
                        help="Path to the folder where generated test.yaml should be put")
    parser.add_argument("--eventtype-only", default=None, action="store_true",
                        help="Create filter blocks based on event types only")
    parser.add_argument("--allow-events", nargs="?", default=None,
                        help="Create filter blocks for the specified events")

    # add arg to allow stdout only
    args = parser.parse_args()

    return args


def test_yaml_format(func):
    def decorated(*args, **kwargs):
        eve_list = func(kwargs["eve_ds"])
        all_eve_list = []
        for item in eve_list:
            eve_dict = {
                    "filter": {
                        "count": item[1],
                        "match": item[0],
                        },
                    }
            all_eve_list.append(eve_dict)
        all_eve_dict = {"checks": all_eve_list}
        all_eve_yaml = yaml.dump(all_eve_dict, default_flow_style=False)
        return all_eve_yaml
    return decorated


@test_yaml_format
def get_eve_list_by_type(eve_ds):
    eve_list = []
    for k, v in eve_ds.items():
        eve_list.append((k, v))
    return eve_list


@test_yaml_format
def get_all_eve_list(eve_ds):
    eve_list = []
    for item in eve_ds:
        eve_list.append((item, 1))
    return eve_list


def get_manipulated_list():
    """
    Manipulate eve.json to load successfully in json and skip the fields
    mentioned in skip_fields variable.
    """
    eve_path = args["path-to-eve"]
    allow_events = args["allow_events"].strip().split(",") if args["allow_events"] else []
    with open(eve_path, "r") as fp:
        content = fp.read()
    content_list = content.strip().split("\n")
    jcontent_list = [json.loads(e) for e in content_list]
    all_content_list = []
    for e in jcontent_list:
        md = {k: v for k, v in e.items() if k not in skip_fields}
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
    Create a filter block based on all the parameters of any event.
    """
    mlist = get_manipulated_list()
    all_eve_list = get_all_eve_list(eve_ds=mlist)
    write_to_file(data=all_eve_list)


def write_to_file(data):
    """
    Check for the output file if it exists, else create one and writw
    to it.
    """
    output_path = args["output-path"]
    try:
        os.remove(output_path)
    except FileNotFoundError:
        logger.info("{} not found. Creating...".format(output_path))
    with open(output_path, "w+") as fp:
        fp.write("# *** Add configuration here ***\n\n")
        fp.write(data)


def filter_event_type(event_types):
    """
    Filter based only on the event types.
    """
    all_eve_list = get_eve_list_by_type(eve_ds=event_types)
    write_to_file(data=all_eve_list)


def process_eve():
    """
    Process the provided eve.json file and write the required checks in the
    provided output file.
    """
    content = list()
    eventtype_only = args["eventtype_only"]
    eve_path = args["path-to-eve"]
    event_types = defaultdict(int)
    with open(eve_path, "r") as fp:
        for line in fp:
            eve_rule = json.loads(line)
            content.append(eve_rule)
            eve_type = eve_rule.get("event_type")
            event_types[eve_type] += 1
    if eventtype_only:
        if args["allow_events"]:
            logger.warning("--allow-events shall not be used with --eventtype-only")
        filter_event_type(event_types=event_types)
        return
    filter_event_type_params(eve_rules=content)


def main():
    global args
    args = vars(parse_args())
    init_logger()
    process_eve()


if __name__ == "__main__":
    main()
