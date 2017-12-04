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
from collections import namedtuple

import yaml

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

def pipe_reader(fileobj, output=None, verbose=False):
    for line in fileobj:
        if output:
            output.write(line)
        if verbose:
            print(line.strip())

class TestConfig:

    def __init__(self, config, suricata_config):
        self.config = config
        self.suricata_config = suricata_config

    def check_requires(self):
        if "requires" in self.config:
            requires = self.config["requires"]

            if "min-version" in requires:
                min_version = parse_suricata_version(requires["min-version"])
                suri_version = self.suricata_config.version
                if not self._version_gte(suri_version, min_version):
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
                        raise UnsatisfiedRequirementError(
                            "not for feature %s" % (feature))

    def has_command(self):
        return "command" in self.config

    def get_command(self):
        return self.config["command"]

    def _version_gte(self, v1, v2):
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
                
class SuricataConfig:

    def __init__(self, version):
        self.version = version
        self.features = set()

        self.load_build_info()

    def load_build_info(self):
        output = subprocess.check_output(["./src/suricata", "--build-info"])
        for line in output.splitlines():
            if line.startswith("Features:"):
                self.features = set(line.split()[1:])

    def has_feature(self, feature):
        return feature in self.features

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

    def run(self):

        sys.stdout.write("===> %s: " % os.path.basename(self.directory))
        sys.stdout.flush()

        if os.path.exists(os.path.join(self.directory, "test.yaml")):
            test_config = yaml.load(
                open(os.path.join(self.directory, "test.yaml"), "rb"))
            test_config = TestConfig(test_config, self.suricata_config)
        else:
            test_config = TestConfig({}, self.suricata_config)

        test_config.check_requires()

        # Additional requirement checks.
        # - If lua is in the test name, make sure we HAVE_LUA.
        if self.directory.find("lua"):
            if not self.suricata_config.has_feature("HAVE_LUA"):
                raise UnsatisfiedRequirementError("requires feature HAVE_LUA")

        shell = False

        if test_config.has_command():
            args = test_config.get_command()
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

        # Cleanup the output directory.
        if os.path.exists(self.output):
            shutil.rmtree(self.output)
        os.makedirs(self.output)

        stdout = open(os.path.join(self.output, "stdout"), "w")
        stderr = open(os.path.join(self.output, "stderr"), "w")

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

        return self.check()

    def check(self):
        if not os.path.exists(os.path.join(self.directory, "check.sh")):
            print("OK")
            return True
        r = subprocess.call(["./check.sh"], cwd=self.directory)
        if r != 0:
            print("FAILED: verification failed")
            return False
        print("OK")
        return True
        
    def default_args(self):
        args = [
            os.path.join(self.cwd, "src/suricata"),
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
        if not pcaps:
            raise Exception("No pcap file found")
        elif len(pcaps) > 1:
            raise Exception("More than 1 pcap file found")
        args += ["-r", pcaps[0]]

        # Find rules.
        rules = glob.glob(os.path.join(self.directory, "*.rules"))
        if not rules:
            args += ["-S", "/dev/null"]
        elif len(rules) == 1:
            args += ["-S", rules[0]]
        else:
            raise Exception("More than 1 rule file found")

        return args

    def start_reader(self, input, output):
        t = threading.Thread(
            target=pipe_reader, args=(input, output, self.verbose))
        t.start()
        self.readers.append(t)

def check_skip(directory):
    return os.path.exists(os.path.join(directory, "skip"))

def main():

    parser = argparse.ArgumentParser(description="Verification test runner.")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("--force", dest="force", action="store_true",
                        help="Force running of skipped tests")
    parser.add_argument("--fail", action="store_true",
                        help="Exit on test failure")
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

    for dirpath, dirnames, filenames in os.walk(os.path.join(topdir, "tests")):

        # The top directory is not a test...
        if dirpath == os.path.join(topdir, "tests"):
            continue

        # We only want to go one level deep.
        dirnames[0:] = []

        name = os.path.basename(dirpath)

        do_test = False
        if not args.patterns:
            if args.force:
                do_test = True
            else:
                if check_skip(dirpath):
                    print("===> %s: SKIPPED" % (name))
                else:
                    do_test = True
        else:
            # If a test matches a pattern, we do not skip it.
            for pattern in args.patterns:
                if name.find(pattern) > -1:
                    if check_skip(dirpath):
                        skipped += 1
                        print("===> %s: SKIPPED" % (name))
                    else:
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
            except UnsatisfiedRequirementError as err:
                print("SKIPPED: %s" % (str(err)))
                skipped += 1
            except Exception as err:
                print("FAIL: exception: %s" % (str(err)))
                failed += 1
                if args.fail:
                    return 1

    print("")
    print("PASSED:  %d" % (passed))
    print("FAILED:  %d" % (failed))
    print("SKIPPED: %d" % (skipped))

    if failed > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
