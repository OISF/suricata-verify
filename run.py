#! /usr/bin/env python2
#
# Copyright 2017 Jason Ish
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

from __future__ import print_function

import sys
import os
import os.path
import subprocess
import threading
import shutil
import argparse
import yaml
import glob
import re
import json
from collections import namedtuple

import yaml

class TestError(Exception):
    pass

class UnsatisfiedRequirementError(Exception):
    pass

SuricataVersion = namedtuple(
    "SuricataVersion", ["major", "minor", "patch", "full", "short", "raw"])

def parse_suricata_version(buf):
    m = re.search("((\d+)\.(\d+)(\.(\d+))?(\w+)?)", str(buf).strip())
    if m:
        full = m.group(1)
        major = int(m.group(2))
        minor = int(m.group(3))
        if not m.group(5):
            patch = 0
        else:
            patch = int(m.group(5))
        short = "%s.%s" % (major, minor)
        return SuricataVersion(
            major=major, minor=minor, patch=patch, short=short, full=full,
            raw=buf)
    return None

def get_suricata_version():
    output = subprocess.check_output(["./src/suricata", "-V"])
    return parse_suricata_version(output)

def version_gte(v1, v2):
    """Return True if v1 is great than or equal to v2."""
    if v1.major < v2.major:
        return False
    elif v1.major > v2.major:
        return True

    if v1.minor < v2.minor:
        return False
    elif v1.minor > v2.minor:
        return True

    if v1.patch < v2.patch:
        return False

    return True

def pipe_reader(fileobj, output=None, verbose=False):
    for line in fileobj:
        line = line.decode()
        if output:
            output.write(line)
        if verbose:
            print(line.strip())

class SuricataConfig:

    def __init__(self, version):
        self.version = version
        self.features = set()

        self.load_build_info()

    def load_build_info(self):
        output = subprocess.check_output(["./src/suricata", "--build-info"])
        for line in output.splitlines():
            if line.decode().startswith("Features:"):
                self.features = set(line.decode().split()[1:])

    def has_feature(self, feature):
        return feature in self.features

def find_value(name, obj):
    """Find the value in an object for a field specified by name.

    Example names:
      event_type
      alert.signature_id
      smtp.rcpt_to[0]
    """
    parts = name.split(".")
    for part in parts:
        name = None
        index = None
        m = re.match("^(.*)\[(\d+)\]$", part)
        if m:
            name = m.group(1)
            index = m.group(2)
        else:
            name = part

        if not name in obj:
            return None
        obj = obj[name]

        if index is not None:
            obj = obj[int(index)]

    return obj

class ShellCheck:

    def __init__(self, config):
        self.config = config

    def run(self):
        try:
            output = subprocess.check_output(self.config["args"], shell=True)
            if "expect" in self.config:
                return str(self.config["expect"]) == output.decode().strip()
            return True
        except subprocess.CalledProcessError as err:
            raise TestError(err)

class StatsCheck:

    def __init__(self, config):
        self.config = config

    def run(self):
        stats = None
        with open(os.path.join("output", "eve.json"), "r") as fileobj:
            for line in fileobj:
                event = json.loads(line)
                if event["event_type"] == "stats":
                    stats = event["stats"]
        for key in self.config:
            val = find_value(key, stats)
            if val != self.config[key]:
                raise TestError("stats.%s: expected %s; got %s" % (
                    key, str(self.config[key]), str(val)))
        return True

class FilterCheck:

    def __init__(self, config):
        self.config = config

    def run(self):
        eve_json_path = os.path.join("output", "eve.json")
        if not os.path.exists(eve_json_path):
            raise TestError("%s does not exist" % (eve_json_path))

        count = 0
        with open(eve_json_path, "r") as fileobj:
            for line in fileobj:
                event = json.loads(line)
                if self.match(event):
                    count += 1
        if count == self.config["count"]:
            return True
        if "comment" in self.config:
            raise TestError("%s: expected %d, got %d" % (
                self.config["comment"], self.config["count"], count))
        raise TestError("expected %d matches; got %d for filter %s" % (
            self.config["count"], count, str(self.config)))

    def match(self, event):
        for field in self.config["match"]:
            val = find_value(field, event)
            if val is None:
                return False
            if val != self.config["match"][field]:
                return False
        return True

class TestRunner:

    def __init__(self, cwd, directory, suricata_config, verbose=False):
        self.cwd = cwd
        self.directory = directory
        self.suricata_config = suricata_config
        self.verbose = verbose
        self.output = os.path.join(self.directory, "output")

        # The name is just the directory name.
        self.name = os.path.basename(self.directory)

        # List of thread readers.
        self.readers = []

        # Load the test configuration.
        self.load_config()

    def load_config(self):
        if os.path.exists(os.path.join(self.directory, "test.yaml")):
            self.config = yaml.safe_load(
                open(os.path.join(self.directory, "test.yaml"), "rb"))
        else:
            self.config = {}

    def setup(self):
        if "setup" in self.config:
            for setup in self.config["setup"]:
                for command in setup:
                    if command == "script":
                        subprocess.check_call(
                            "%s" % setup[command],
                            shell=True,
                            cwd=self.directory)

    def check_requires(self):
        if not "requires" in self.config:
            return
        requires = self.config["requires"]

        if "min-version" in requires:
            min_version = parse_suricata_version(requires["min-version"])
            suri_version = self.suricata_config.version
            if not version_gte(suri_version, min_version):
                raise UnsatisfiedRequirementError(
                    "requires at least version %s" % (min_version.raw))

        if "features" in requires:
            for feature in requires["features"]:
                if not self.suricata_config.has_feature(feature):
                    raise UnsatisfiedRequirementError(
                        "requires feature %s" % (feature))

        if "not-features" in requires:
            for feature in requires["not-features"]:
                if self.suricata_config.has_feature(feature):
                    if requires["not-features"][feature]:
                        comment = "%s" % (
                            requires["not-features"][feature])
                    else:
                        comment = "not for feature %s" % (feature)
                    raise UnsatisfiedRequirementError(comment)

        if "env" in requires:
            for env in requires["env"]:
                if not env in os.environ:
                    raise UnsatisfiedRequirementError(
                        "requires env var %s" % (env))

        if "files" in requires:
            for filename in requires["files"]:
                if not os.path.exists(filename):
                    raise UnsatisfiedRequirementError(
                        "requires file %s" % (filename))

        # Check if a pcap is required or not. By default a pcap is
        # required unless a "command" has been provided.
        if not "command" in self.config:
            if "pcap" in requires:
                pcap_required = requires["pcap"]
            else:
                pcap_required = True
            if pcap_required:
                if not glob.glob(os.path.join(self.directory, "*.pcap")):
                    raise UnsatisfiedRequirementError("No pcap file found")

    def run(self):

        sys.stdout.write("===> %s: " % os.path.basename(self.directory))
        sys.stdout.flush()

        # Cleanup the output directory.
        if os.path.exists(self.output):
            shutil.rmtree(self.output)
        os.makedirs(self.output)

        self.check_requires()
        self.setup()

        shell = False

        if "command" in self.config:
            args = self.config["command"]
            shell = True
        else:
            args = self.default_args()

        env = {
            # The suricata source directory.
            "SRCDIR": self.cwd,
            "TZ": "UTC",
            "TEST_DIR": self.directory,
            "ASAN_OPTIONS": "detect_leaks=0",
        }

        stdout = open(os.path.join(self.output, "stdout"), "w")
        stderr = open(os.path.join(self.output, "stderr"), "w")

        if "count" in self.config:
            count = self.config["count"]
        else:
            count = 1

        for _ in range(count):

            open(os.path.join(self.output, "cmdline"), "w").write(
                " ".join(args))

            p = subprocess.Popen(
                args, shell=shell, cwd=self.directory, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            self.start_reader(p.stdout, stdout)
            self.start_reader(p.stderr, stderr)

            for r in self.readers:
                r.join()

            r = p.wait()

            if r != 0:
                print("FAIL: process returned with non-0 exit code: %d" % r)
                return False

            if not self.check():
                return False

        print("OK%s" % (" (%dx)" % count if count > 1 else ""))
        return True

    def check(self):

        pdir = os.getcwd()
        os.chdir(self.directory)
        try:
            if "checks" in self.config:
                for check in self.config["checks"]:
                    for key in check:
                        if key == "filter":
                            if not FilterCheck(check[key]).run():
                                raise TestError("filter did not match: %s" % (
                                    str(check[key])))
                        elif key == "shell":
                            if not ShellCheck(check[key]).run():
                                raise TestError(
                                    "shell output did not match: %s" % (
                                        str(check[key])))
                        elif key == "stats":
                            if not StatsCheck(check[key]).run():
                                raise TestError("stats check did not pass")
                        else:
                            raise TestError("Unknown check type: %s" % (key))
        finally:
            os.chdir(pdir)

        if not os.path.exists(os.path.join(self.directory, "check.sh")):
            return True
        r = subprocess.call(["./check.sh"], cwd=self.directory)
        if r != 0:
            print("FAILED: verification failed")
            return False
        return True
        
    def default_args(self):
        args = [
            os.path.join(self.cwd, "src/suricata"),
        ]

        # Load args from config file.
        if "args" in self.config:
            assert(type(self.config["args"]) == type([]))
            for arg in self.config["args"]:
                args += re.split("\s", arg)

        # Add other fixed arguments.
        args += [
            "--set", "classification-file=%s" % os.path.join(
                self.cwd, "classification.config"),
            "--set", "reference-config-file=%s" % os.path.join(
                self.cwd, "reference.config"),
            "--init-errors-fatal",
            "-l", self.output,
        ]

        if "ips" in self.name:
            args.append("--simulate-ips")

        if os.path.exists(os.path.join(self.directory, "suricata.yaml")):
            args += ["-c", os.path.join(self.directory, "suricata.yaml")]
        else:
            args += ["-c", os.path.join(self.cwd, "suricata.yaml")]

        # Find pcaps.
        pcaps = glob.glob(os.path.join(self.directory, "*.pcap"))
        if len(pcaps) > 1:
            raise TestError("More than 1 pcap file found")
        if pcaps:
            args += ["-r", pcaps[0]]

        # Find rules.
        rules = glob.glob(os.path.join(self.directory, "*.rules"))
        if not rules:
            args += ["-S", "/dev/null"]
        elif len(rules) == 1:
            args += ["-S", rules[0]]
        else:
            raise TestError("More than 1 rule file found")

        return args

    def start_reader(self, input, output):
        t = threading.Thread(
            target=pipe_reader, args=(input, output, self.verbose))
        t.start()
        self.readers.append(t)

def check_deps():
    try:
        subprocess.check_call("jq --version > /dev/null 2>&1", shell=True)
    except:
        print("error: jq is required")
        return False

    try:
        subprocess.check_call("echo | xargs > /dev/null 2>&1", shell=True)
    except:
        print("error: xargs is required")
        return False

    return True

def main():

    if not check_deps():
        return 1

    parser = argparse.ArgumentParser(description="Verification test runner.")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("--force", dest="force", action="store_true",
                        help="Force running of skipped tests")
    parser.add_argument("--fail", action="store_true",
                        help="Exit on test failure")
    parser.add_argument("--dir", action="store",
                        help="Runs tests from custom directory")
    parser.add_argument("patterns", nargs="*", default=[])
    args = parser.parse_args()

    topdir = os.path.abspath(os.path.dirname(sys.argv[0]))
    
    skipped = 0
    passed = 0
    failed = 0

    # Get the current working directory, which should be the top
    # suricata source directory.
    cwd = os.getcwd()
    if not (os.path.exists("./suricata.yaml") and
            os.path.exists("./src/suricata")):
        print("error: this is not a suricata source directory or " +
              "suricata is not built")
        return 1

    # Create a SuricataConfig object that is passed to all tests.
    suricata_config = SuricataConfig(get_suricata_version())

    tdir = os.path.join(topdir, "tests")
    if args.dir:
        tdir = os.path.abspath(args.dir)

    for dirpath, dirnames, filenames in os.walk(tdir):

        # The top directory is not a test...
        if dirpath == os.path.join(topdir, "tests"):
            continue
        if dirpath == tdir:
            continue

        # We only want to go one level deep.
        dirnames[0:] = []

        name = os.path.basename(dirpath)

        do_test = False
        if not args.patterns:
            do_test = True
        else:
            # If a test matches a pattern, we do not skip it.
            for pattern in args.patterns:
                if name.find(pattern) > -1:
                    do_test = True
                    break

        if do_test:
            test_runner = TestRunner(
                cwd, dirpath, suricata_config, args.verbose)
            try:
                if test_runner.run():
                    passed += 1
                else:
                    failed += 1
                    if args.fail:
                        return 1
            except UnsatisfiedRequirementError as err:
                print("SKIPPED: %s" % (str(err)))
                skipped += 1
            except TestError as err:
                print("FAIL: %s" % (str(err)))
                failed += 1
                if args.fail:
                    return 1
            except Exception as err:
                raise

    print("")
    print("PASSED:  %d" % (passed))
    print("FAILED:  %d" % (failed))
    print("SKIPPED: %d" % (skipped))

    if failed > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
