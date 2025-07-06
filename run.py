#! /usr/bin/env python3
#
# Copyright (C) 2017-2022 Open Information Security Foundation
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
import string
import argparse
import yaml
import glob
import re
import json
import unittest
import multiprocessing as mp
from collections import namedtuple
import threading
import filecmp
import subprocess
import yaml
import traceback
import platform

VALIDATE_EVE = False
# Windows and macOS don't support the mp logic below.
WIN32 = sys.platform == "win32"
DARWIN = sys.platform == "darwin"
MP = not WIN32 and not DARWIN
suricata_yaml = "suricata.yaml" if WIN32 else "./suricata.yaml"

# Determine the Suricata binary
if os.path.exists("src\\suricata.exe"):
    suricata_bin = "src\\suricata.exe"
else:
    suricata_bin = "./src/suricata"

PROC_TIMEOUT=300

if MP:
    manager = mp.Manager()
    lock = mp.Lock()
    failedLogs = manager.list()
    count_dict = manager.dict()
    check_args = manager.dict()
else:
    failedLogs = []
    count_dict = {}
    check_args = {}
    # Bring in a lock from threading to satisfy the MP semantics when
    # not using MP.
    lock = threading.Lock()

count_dict['passed'] = 0
count_dict['failed'] = 0
count_dict['skipped'] = 0
check_args['fail'] = 0

class SelfTest(unittest.TestCase):

    def test_parse_suricata_version(self):
        version = parse_suricata_version("4.0.0")
        self.assertEqual(
            (4, 0, 0), (version.major, version.minor, version.patch))

        version = parse_suricata_version("444.444.444")
        self.assertEqual(
            (444, 444, 444), (version.major, version.minor, version.patch))

        version = parse_suricata_version("4.1.0-dev")
        self.assertEqual(
            (4, 1, 0), (version.major, version.minor, version.patch))

        version = parse_suricata_version("4")
        self.assertEqual(
            (4, 0, 0), (version.major, version.minor, version.patch))

        version = parse_suricata_version("4.0.3")
        self.assertEqual(
            (4, 0, 3), (version.major, version.minor, version.patch))

    def test_version_equal(self):
        self.assertTrue(Version().is_equal(SuricataVersion(5, 0, 0), SuricataVersion(5, 0, 0)))
        self.assertTrue(Version().is_equal(SuricataVersion(5, 1, 0), SuricataVersion(5, None, None)))
        self.assertFalse(Version().is_equal(SuricataVersion(4, 1, 0), SuricataVersion(5, None, None)))

    def test_version_gt(self):
        comp = Version()
        self.assertTrue(comp.is_gt(SuricataVersion(6, None, None), SuricataVersion(5, None, None)))
        self.assertTrue(comp.is_gt(SuricataVersion(6, None, None), SuricataVersion(5, 0, 3)))
        self.assertTrue(comp.is_gt(SuricataVersion(6, 0, 1), SuricataVersion(6, 0, 0)))
        self.assertFalse(comp.is_gt(SuricataVersion(6, 0, 1), SuricataVersion(6, 0, 1)))
        self.assertTrue(comp.is_gt(SuricataVersion(6, 1, 0), SuricataVersion(6, 0, 1)))

    def test_version_gte(self):
        comp = Version()
        self.assertTrue(comp.is_gte(SuricataVersion(6, None, None), SuricataVersion(5, None, None)))
        self.assertTrue(comp.is_gte(SuricataVersion(6, 0, 1), SuricataVersion(6, 0, 0)))
        self.assertTrue(comp.is_gte(SuricataVersion(6, 0, 1), SuricataVersion(6, 0, 1)))
        self.assertTrue(comp.is_gte(SuricataVersion(6, 1, 0), SuricataVersion(6, 0, 1)))

    def test_version_lt(self):
        comp = Version()
        self.assertTrue(comp.is_lt(SuricataVersion(5, 0, 3), SuricataVersion(6, None, None)))
        self.assertTrue(comp.is_lt(SuricataVersion(6, 0, 0), SuricataVersion(6, 0, 1)))
        self.assertTrue(comp.is_lt(SuricataVersion(6, 0, 0), SuricataVersion(6, 1, 1)))
        self.assertFalse(comp.is_lt(SuricataVersion(6, 1, 2), SuricataVersion(6, 1, 1)))
        self.assertTrue(comp.is_lt(SuricataVersion(6, 0, 0), SuricataVersion(7, 0, 0)))

class TestError(Exception):
    pass

class UnsatisfiedRequirementError(Exception):
    pass

class ImpossibleRequirementError(Exception):
    pass

class UnnecessaryRequirementError(Exception):
    pass

class TerminatePoolError(Exception):
    pass

SuricataVersion = namedtuple(
    "SuricataVersion", ["major", "minor", "patch"])

def parse_suricata_version(buf, expr=None):
    m = re.search(r"(?:Suricata version |^)(\d+)\.?(\d+)?\.?(\d+)?.*", str(buf).strip())
    default_v = 0
    if expr is not None and expr == "equal":
        default_v = None
    if m:
        major = int(m.group(1)) if m.group(1) else default_v
        minor = int(m.group(2)) if m.group(2) else default_v
        patch = int(m.group(3)) if m.group(3) else default_v

        return SuricataVersion(
            major=major, minor=minor, patch=patch)

    return None

def get_suricata_version():
    output = subprocess.check_output([suricata_bin, "-V"])
    return parse_suricata_version(output)


def pipe_reader(fileobj, output=None, verbose=False, utf8_errors=[]):
    for line in fileobj:
        if output:
            output.write(line)
            output.flush()
        if verbose:
            try:
                line = line.decode().strip()
            except:
                self.utf8_errors.append("Invalid line")
            print(line)


def handle_exceptions(func):
    def applicator(*args, **kwargs):
        result = False
        try:
            result = func(*args,**kwargs)
        except TestError as te:
            print("===> {}: Sub test #{}: FAIL : {}".format(kwargs["test_name"], kwargs["test_num"], te))
            check_args_fail()
            kwargs["count"]["failure"] += 1
        except UnsatisfiedRequirementError as ue:
            if args and not args[0].quiet:
                print("===> {}: Sub test #{}: SKIPPED : {}".format(kwargs["test_name"], kwargs["test_num"], ue))
            kwargs["count"]["skipped"] += 1
        except Exception as err:
            raise TestError("Internal runtime error: {}".format(err))
        else:
            if result:
              kwargs["count"]["success"] += 1
            else:
              print("\n===> {}: Sub test #{}: FAIL : {}".format(kwargs["test_name"], kwargs["test_num"], kwargs["check"]["args"]))
              kwargs["count"]["failure"] += 1
        return kwargs["count"]
    return applicator


class Version:
    """
    Class to compare Suricata versions.
    """
    def is_equal(self, a, b):
        """Check if version a and version b are equal in a semantic way.

        For example:
          - 4 would match 4, 4.x and 4.x.y.
          - 4.0 would match 4.0.x.
          - 4.0.3 would match only 4.0.3.
        """
        if not a.major == b.major:
            return False

        if a.minor is not None and b.minor is not None:
            if a.minor != b.minor:
                return False

        if a.patch is not None and b.patch is not None:
            if a.patch != b.patch:
                return False

        return True

    def is_gte(self, v1, v2):
        """Return True if v1 is greater than or equal to v2."""
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

    def is_gt(self, v1, v2):
        """Return True if v1 is greater than v2."""
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
        elif v1.patch == v2.patch:
            return False

        return True

    def is_lt(self, v1, v2):
        """Return True if v1 is less than v2."""
        if v1.major > v2.major:
            return False
        elif v1.major < v2.major:
            return True
        elif v1.minor < v2.minor:
            return True
        elif v1.patch < v2.patch:
            return True
        return False

class SuricataConfig:

    def __init__(self, version):
        self.version = version
        self.features = set()
        self.config = {}
        self.load_build_info()

    def load_build_info(self):
        output = subprocess.check_output([suricata_bin, "--build-info"])
        start_support = False
        for line in output.splitlines():
            if line.decode().startswith("Features:"):
                self.features = set(line.decode().split()[1:])
            if "Suricata Configuration" in line.decode():
                start_support = True
            if start_support and "support:" in line.decode():
                (fkey, val) = line.decode().split(" support:")
                fkey = fkey.strip()
                val = val.strip()
                if val.startswith("yes"):
                    self.features.add(fkey)

    def load_config(self, config_filename):
        output = subprocess.check_output([
            suricata_bin,
            "-c", config_filename,
            "--dump-config"])
        self.config = {}
        for line in output.decode("utf-8").split("\n"):
            parts = [p.strip() for p in line.split("=", 1)]
            if parts and parts[0]:
                if len(parts) > 1:
                    val = parts[1]
                else:
                    val = ""
                self.config[parts[0]] = val

    def has_feature(self, feature):
        return feature in self.features


def check_filter_test_version_compat(requires, test_version):
    for key in requires:
        # TODO more tests, including linter tests of redundant min-version
        if key == "lt-version":
            if "min" in test_version:
                if not is_version_compatible(version=requires["lt-version"], suri_version=parse_suricata_version(test_version["min"]), expr="lt"):
                    raise ImpossibleRequirementError(
                        "test requires min {} check requires lt-version {}".format(test_version["min"], requires["lt-version"]))
        elif key == "min-version":
            if "min" in test_version:
                if requires["min-version"] == test_version["min"]:
                    raise UnnecessaryRequirementError(
                        "test already requires min {} not needed for the check {}".format(test_version["min"], requires["min-version"]))

def check_requires(requires, suricata_config: SuricataConfig):
    suri_version = suricata_config.version
    for key in requires:
        if key == "min-version":
            min_version = requires["min-version"]
            if not is_version_compatible(version=min_version,
                    suri_version=suri_version, expr="gte"):
                raise UnsatisfiedRequirementError(
                        "requires at least version {}".format(min_version))
        elif key == "lt-version":
            lt_version = requires["lt-version"]
            if not is_version_compatible(version=lt_version,
                    suri_version=suri_version, expr="lt"):
                raise UnsatisfiedRequirementError(
                        "for version less than {}".format(lt_version))
        elif key == "gt-version":
            gt_version = requires["gt-version"]
            if not is_version_compatible(version=gt_version,
                    suri_version=suri_version, expr="gt"):
                raise UnsatisfiedRequirementError(
                        "for version great than {}".format(gt_version))
        elif key == "version":
            req_version = requires["version"]
            if not is_version_compatible(version=req_version,
                    suri_version=suri_version, expr="equal"):
                raise UnsatisfiedRequirementError(
                        "only for version {}".format(req_version))
        elif key == "features":
            for feature in requires["features"]:
                if not suricata_config.has_feature(feature):
                    raise UnsatisfiedRequirementError(
                        "requires feature %s" % (feature))
        elif key == "env":
            for env in requires["env"]:
                if not env in os.environ:
                    raise UnsatisfiedRequirementError(
                        "requires env var %s" % (env))
        elif key == "files":
            for filename in requires["files"]:
                if not os.path.exists(filename):
                    raise UnsatisfiedRequirementError(
                        "requires file %s" % (filename))
        elif key == "script":
            for script in requires["script"]:
                try:
                    subprocess.check_call("%s" % script, shell=True)
                except:
                    raise UnsatisfiedRequirementError(
                        "requires script returned false")
        elif key == "pcap":
            # A valid requires argument, but not verified here.
            pass
        elif key == "lambda":
            if not eval(requires["lambda"]):
                raise UnsatisfiedRequirementError(requires["lambda"])
        elif key == "os":
            cur_platform = platform.system().lower()
            if not cur_platform.startswith(requires["os"].lower()):
                raise UnsatisfiedRequirementError(requires["os"])
        elif key == "arch":
            cur_arch = platform.machine().lower()
            if not cur_arch.startswith(requires["arch"].lower()):
                raise UnsatisfiedRequirementError(requires["arch"])
        else:
            raise Exception("unknown requires types: %s" % (key))


def find_value(name, obj):
    """Find the value in an object for a field specified by name.

    Example names:
      event_type
      alert.signature_id
      smtp.rcpt_to[0]
    """
    parts = name.split(".")
    for part in parts:

        if part == "__len":
            # Get the length of the object. Return -1 if the object is
            # not a type that has a length (numbers).
            try:
                return len(obj)
            except:
                return -1
        if part in ["__contains", "__find", "__startswith", "__endswith"]:
            # Return full object, caller will handle the special match logic.
            break
        name = None
        index = None
        m = re.match(r"^(.*)\[(\d+)\]$", part)
        if m:
            name = m.group(1)
            index = m.group(2)
        else:
            name = part

        if not name in obj:
            return None
        obj = obj[name]

        if index is not None:
            try:
                obj = obj[int(index)]
            except:
                return None

    return obj


def is_version_compatible(version, suri_version, expr):
    config_version = parse_suricata_version(version, expr)
    version_obj = Version()
    func = getattr(version_obj, "is_{}".format(expr))
    if not func(suri_version, config_version):
        return False
    return True

def rule_is_version_compatible(rulefile, suri_version):
    if rulefile.startswith("min"):
        # strip prefix min and suffix .rules
        return is_version_compatible(rulefile[3:-6], suri_version, "gte")
    # default is true
    return True

class FileCompareCheck:

    def __init__(self, config, directory):
        self.config = config
        self.directory = directory

    def run(self):
        if WIN32:
            raise UnsatisfiedRequirementError("shell check not supported on Windows")
        expected = os.path.join(self.directory, self.config["expected"])
        filename = self.config["filename"]
        try:
            if filecmp.cmp(expected, filename):
                return True
            else:
                raise TestError("%s %s \nFAILED: verification failed" % (expected, filename))
        except Exception as err:
            raise TestError("file-compare check failed with exception: %s" % (err))

class ShellCheck:

    def __init__(self, config, env, suricata_config):
        self.config = config
        self.env = env
        self.suricata_config = suricata_config

    def run(self):
        shell_args = {}
        if not self.config or "args" not in self.config:
            raise TestError("shell check missing args")
        req_version = self.config.get("version")
        min_version = self.config.get("min-version")
        lt_version = self.config.get("lt-version")
        if req_version is not None:
            shell_args["version"] = req_version
        if min_version is not None:
            shell_args["min-version"] = min_version
        if lt_version is not None:
            shell_args["lt-version"] = lt_version
        check_requires(shell_args, self.suricata_config)

        try:
            if WIN32:
                raise UnsatisfiedRequirementError("shell check not supported on Windows")
            output = subprocess.check_output(self.config["args"], shell=True, env=self.env)
            if "expect" in self.config:
                return str(self.config["expect"]) == output.decode().strip()
            return True
        except subprocess.CalledProcessError as err:
            raise TestError("Shell command failed: {} -> {}".format(
                self.config, err.output))

class StatsCheck:

    def __init__(self, config, outdir):
        self.config = config
        self.outdir = outdir

    def run(self):
        stats = None
        with open("eve.json", "r") as fileobj:
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

    def __init__(self, config, outdir, suricata_config, test_version):
        self.config = config
        self.outdir = outdir
        self.suricata_config = suricata_config
        self.suri_version = suricata_config.version
        self.test_version = test_version

    def run(self):
        requires = self.config.get("requires", {})
        req_version = self.config.get("version")
        min_version = self.config.get("min-version")
        lt_version = self.config.get("lt-version")
        if req_version is not None:
            requires["version"] = req_version
        if min_version is not None:
            requires["min-version"] = min_version
        if lt_version is not None:
            requires["lt-version"] = lt_version
        check_filter_test_version_compat(requires, self.test_version)
        feature = self.config.get("feature")
        if feature is not None:
            requires["features"] = [feature]
        check_requires(requires, self.suricata_config)

        if "filename" in self.config:
            json_filename = self.config["filename"]
        else:
            json_filename = "eve.json"
        if not os.path.exists(json_filename):
            raise TestError("%s does not exist" % (json_filename))

        count = 0
        with open(json_filename, "r", encoding="utf-8") as fileobj:
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
        for key, expected in self.config["match"].items():
            if key == "has-key":
                val = find_value(expected, event)
                if val is None:
                    return False
            elif key == "not-has-key":
                val = find_value(expected, event)
                if val is not None:
                    return False
            else:
                val = find_value(key, event)
                if key.endswith("__find"):
                    if val.find(expected) < 0:
                        return False
                elif key.endswith("__contains"):
                    if not expected in val:
                        return False
                elif key.endswith("__startswith"):
                    if not val.startswith(expected):
                        return False
                elif key.endswith("__endswith"):
                    if not val.endswith(expected):
                        return False
                elif val != expected:
                    if str(val) == str(expected):
                        print("Different types but same string", type(val), val, type(expected), expected)
                    return False
        return True

class TestRunner:

    def __init__(self, cwd, directory, outdir, suricata_config, verbose=False,
                 force=False, quiet=False):
        self.cwd = cwd
        self.directory = directory
        self.suricata_config = suricata_config
        self.verbose = verbose
        self.utf8_errors = []
        self.force = force
        self.output = outdir
        self.quiet = quiet
        # version requirements for test, to check compatibility with checks requirements
        self.version = {}

        # The name is just the directory name.
        self.name = os.path.basename(self.directory)

        # List of thread readers.
        self.readers = []

        # Load the test configuration.
        self.config = None
        self.load_config()

        self.suricata_config.load_config(self.get_suricata_yaml_path())

    def load_config(self):
        if os.path.exists(os.path.join(self.directory, "test.yaml")):
            try:
                self.config = yaml.safe_load(
                    open(os.path.join(self.directory, "test.yaml"), "rb"))
            except yaml.scanner.ScannerError as e:
                print(str(e))
        if self.config is None:
            self.config = {}

    def setup(self):
        if "setup" in self.config:
            for setup in self.config["setup"]:
                for command in setup:
                    if command == "script":
                        subprocess.check_call(
                            "%s" % setup[command],
                            shell=True,
                            cwd=self.output)

    def check_skip(self):
        if not "skip" in self.config:
            return
        if isinstance(self.config["skip"], bool):
            if self.config["skip"]:
                raise UnsatisfiedRequirementError("skipped by default")
            return
        for skip in self.config["skip"]:

            if "uid" in skip:
                if WIN32:
                    raise UnsatisfiedRequirementError("uid based skip not supported on Windows")
                if os.getuid() == skip["uid"]:
                    if "msg" in skip:
                        msg = skip["msg"]
                    else:
                        msg = "not for uid %d" % (skip["uid"])
                    raise UnsatisfiedRequirementError(msg)

            if "feature" in skip:
                if self.suricata_config.has_feature(skip["feature"]):
                    if "msg" in skip:
                        msg = skip["msg"]
                    else:
                        msg = "not for feature %s" % (skip["feature"])
                    raise UnsatisfiedRequirementError(msg)

            if "config" in skip:
                for pattern, need_val in skip["config"].items():
                    for key, val in self.suricata_config.config.items():
                        if re.match(pattern, key):
                            if str(need_val) == str(val):
                                raise UnsatisfiedRequirementError(
                                    "not for %s = %s" % (
                                        key, need_val))

    def check_requires(self):
        requires = self.config.get("requires", {})
        check_requires(requires, self.suricata_config)
        for key in requires:
            if key == "min-version":
                self.version["min"] = requires["min-version"]
            elif key == "lt-version":
                self.version["lt"] = requires["lt-version"]
            elif key == "gt-version":
                self.version["gt"] = requires["gt-version"]
            elif key == "version":
                self.version["eq"] = requires["version"]

        # Check if a pcap is required or not. By default a pcap is
        # required unless a "command" has been provided.
        if not "command" in self.config:
            if "pcap" in requires:
                pcap_required = requires["pcap"]
            else:
                pcap_required = True

            # As a pcap filename can be specified outside of the requires block, let
            # setting this to false disable the requirement of a pcap as well.
            if "pcap" in self.config and not self.config["pcap"]:
                pcap_required = False
                del(self.config["pcap"])

            if pcap_required and not "pcap" in self.config:
                if not glob.glob(os.path.join(self.directory, "*.pcap")) + \
                   glob.glob(os.path.join(self.directory, "*.pcapng")):
                    raise UnsatisfiedRequirementError("No pcap file found")

    def build_env(self):
        env = os.environ.copy()
        env["SRCDIR"] = self.cwd
        env["TZ"] = "UTC"
        env["TEST_DIR"] = self.directory
        env["OUTPUT_DIR"] = self.output
        if not "ASAN_OPTIONS" in env:
            env["ASAN_OPTIONS"] = "detect_leaks=1"
        if self.config.get("env"):
            for key in self.config["env"]:
                env[key] = str(self.config["env"][key])
        return env

    def run(self, outdir):
        if not self.force:
            self.check_requires()
            self.check_skip()

        if WIN32 and "setup" in self.config:
            raise UnsatisfiedRequirementError("test \"setup\" not supported on Windows")

        shell = False

        if "command" in self.config:
            # on Windows skip 'command' tests
            if WIN32:
                raise UnsatisfiedRequirementError("\"command\" tests are not supported on Windows")

            args = self.config["command"]
            shell = True
        else:
            args = self.default_args()

        env = self.build_env()

        safe_env = {}
        for key in env:
            safe_env[key] = str(env[key])

        if "count" in self.config:
            count = self.config["count"]
        else:
            count = 1

        if "exit-code" in self.config:
            expected_exit_code = self.config["exit-code"]
        else:
            expected_exit_code = 0

        retries = self.config.get("retry", 1)

        while True:
            retries -= 1
            for _ in range(count):

                # Cleanup the output directory.
                if os.path.exists(self.output):
                    shutil.rmtree(self.output)
                os.makedirs(self.output)
                self.setup()

                stdout = open(os.path.join(self.output, "stdout"), "wb")
                stderr = open(os.path.join(self.output, "stderr"), "wb")

                if shell:
                    template = string.Template(args)
                    cmdline = template.substitute(safe_env)
                else:
                    for a in range(len(args)):
                        args[a] = string.Template(args[a]).substitute(safe_env)
                    cmdline = " ".join(args) + "\n"

                open(os.path.join(self.output, "cmdline"), "w").write(cmdline)

                if self.verbose:
                    print("Executing: {}".format(cmdline.strip()))

                p = subprocess.Popen(
                    args, shell=shell, cwd=self.directory, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # used to get a return value from the threads
                self.utf8_errors=[]
                self.start_reader(p.stdout, stdout)
                self.start_reader(p.stderr, stderr)
                for r in self.readers:
                    try:
                        r.join(timeout=PROC_TIMEOUT)
                    except:
                        print("stdout/stderr reader timed out, terminating")
                        r.terminate()

                try:
                    r = p.wait(timeout=PROC_TIMEOUT)
                except:
                    print("Suricata timed out, terminating")
                    p.terminate()
                    raise TestError("timed out when expected exit code %d" % (
                        expected_exit_code));

                if len(self.utf8_errors) > 0:
                     raise TestError("got utf8 decode errors %s" % self.utf8_errors);

                if r != expected_exit_code:
                    raise TestError("got exit code %d, expected %d" % (
                        r, expected_exit_code));

                check_value = self.check()

            if check_value["failure"] and retries > 0:
                print("===> {}: Retrying".format(os.path.basename(self.directory)))
                continue

            if VALIDATE_EVE:
                check_output = subprocess.call([os.path.join(TOPDIR, "check-eve.py"), outdir, "-q", "-s", os.path.join(self.cwd, "etc", "schema.json")])
                if check_output != 0:
                    raise TestError("Invalid JSON schema")

            if not check_value["failure"] and not check_value["skipped"]:
                if not self.quiet:
                    if os.path.basename(os.path.dirname(self.directory)) != "tests":
                        path_name = os.path.join(os.path.basename(os.path.dirname(self.directory)), self.name)
                    else:
                        path_name = (os.path.basename(self.directory))
                    print("===> %s: OK%s" % (path_name, " (%dx)" % count if count > 1 else ""))
            elif not check_value["failure"]:
                if not self.quiet:
                    print("===> {}: OK (checks: {}, skipped: {})".format(os.path.basename(self.directory), sum(check_value.values()), check_value["skipped"]))
            return check_value

    def pre_check(self):
        if "pre-check" in self.config:
            subprocess.call(self.config["pre-check"], shell=True)

    @handle_exceptions
    def perform_filter_checks(self, check, count, test_num, test_name):
        count = FilterCheck(check, self.output,
                self.suricata_config, self.version).run()
        return count

    @handle_exceptions
    def perform_shell_checks(self, check, count, test_num, test_name):
        count = ShellCheck(check, self.build_env(), self.suricata_config).run()
        return count

    @handle_exceptions
    def perform_stats_checks(self, check, count, test_num, test_name):
        count = StatsCheck(check, self.output).run()
        return count

    @handle_exceptions
    def perform_file_compare_checks(self, check, count, test_num, test_name):
        count = FileCompareCheck(check, self.directory).run()
        return count

    def reset_count(self, dictionary):
        for k in dictionary.keys():
            dictionary[k] = 0

    def check(self):
        pdir = os.getcwd()
        os.chdir(self.output)
        count = {
            "success": 0,
            "failure": 0,
            "skipped": 0,
                }
        try:
            self.pre_check()
            if "checks" in self.config:
                self.reset_count(count)
                for check_count, check in enumerate(self.config["checks"]):
                    for key in check:
                        if key in ["filter", "shell", "stats", "file-compare"]:
                            func = getattr(self, "perform_{}_checks".format(key.replace("-","_")))
                            count = func(check=check[key], count=count,
                                    test_num=check_count + 1, test_name=os.path.basename(self.directory))
                        else:
                            print("FAIL: Unknown check type: {}".format(key))
        finally:
            os.chdir(pdir)

        if count["failure"] or count["skipped"]:
            return count

        success_c = count["success"]
        count["success"] = 1 if not success_c else success_c

        return count

    def default_args(self):
        args = []
        if self.suricata_config.valgrind:
            suppression_opt = "--suppressions=%s" % os.path.join(self.cwd, "qa/valgrind.suppress")
            args += [ "valgrind", "-v", "--error-exitcode=255", suppression_opt ]

        args += [
            os.path.join(self.cwd, suricata_bin),
        ]

        # Load args from config file.
        if "args" in self.config:
            assert(type(self.config["args"]) == type([]))
            for arg in self.config["args"]:
                args += re.split(r"\s", arg)

        # In Suricata 5.0 the classification.config and
        # reference.config were moved into the etc/ directory. For now
        # check there and the top level directory to still support
        # 4.1.
        classification_configs = [
            os.path.join(self.cwd, "etc", "classification.config"),
            os.path.join(self.cwd, "classification.config"),
        ]

        for config in classification_configs:
            if os.path.exists(config):
                args += ["--set", "classification-file=%s" % config]
                break

        reference_configs = [
            os.path.join(self.cwd, "etc", "reference.config"),
            os.path.join(self.cwd, "reference.config"),
        ]

        for config in reference_configs:
            if os.path.exists(config):
                args += ["--set", "reference-config-file=%s" % config]
                break

        # Add other fixed arguments.
        args += [
            "--init-errors-fatal",
            "-l", self.output,
        ]

        if "ips" in self.name:
            args.append("--simulate-ips")

        args += ["-c", self.get_suricata_yaml_path()]

        # Find pcaps.
        if "pcap" in self.config:
            try:
                curdir = os.getcwd()
                os.chdir(self.directory)
                if not os.path.exists(self.config["pcap"]):
                    raise TestError("PCAP filename does not exist: {}".format(self.config["pcap"]))
                args += ["-r", os.path.realpath(os.path.join(self.directory, self.config["pcap"]))]
            finally:
                os.chdir(curdir)
        else:
            pcaps = glob.glob(os.path.join(self.directory, "*.pcap"))
            pcaps += glob.glob(os.path.join(self.directory, "*.pcapng"))
            if len(pcaps) > 1:
                raise TestError("More than 1 pcap file found")
            if pcaps:
                args += ["-r", pcaps[0]]

        # Find rules.
        rules = sorted(glob.glob(os.path.join(self.directory, "*.rules")))
        if not rules:
            args.append("--disable-detection")
        elif len(rules) == 1:
            rulefile = rules[0]
            # switch to firewall mode if file is named firewall.rules
            if rulefile.endswith("firewall.rules"):
                args += ["--firewall-rules-exclusive", rulefile]
            elif rule_is_version_compatible(os.path.basename(rulefile), self.suricata_config.version):
                args += ["-S", rulefile]
            else:
                args.append("--disable-detection")
        elif len(rules) == 2:
            rulefile = rules[0]
            # switch to firewall mode if file is named firewall.rules
            if rulefile.endswith("firewall.rules"):
                args += ["--firewall-rules-exclusive", rulefile]
            else:
                raise TestError("multi rule file should have firewall.rules and td.rules. Got {} {}".format(rules[0],rules[1]))

            rulefile = rules[1]
            if rulefile.endswith("td.rules"):
                args += ["-S", rulefile]
            else:
                raise TestError("multi rule file should have firewall.rules and td.rules")
        else:
            raise TestError("More than 1 rule file found")

        return args

    def get_suricata_yaml_path(self):
        """Return the path to the suricata.yaml that will be used for this
        test."""
        if os.path.exists(os.path.join(self.directory, "suricata.yaml")):
            return os.path.join(self.directory, "suricata.yaml")
        return os.path.join(self.cwd, "suricata.yaml")

    def start_reader(self, input, output):
        t = threading.Thread(
            target=pipe_reader, args=(input, output, self.verbose, self.utf8_errors))
        t.start()
        self.readers.append(t)


def check_args_fail():
    if args.fail:
        with lock:
            check_args['fail'] = 1


def check_deps():
    try:
        cmd = "jq --version > nil" if WIN32 else "jq --version > /dev/null 2>&1"
        subprocess.check_call(cmd, shell=True)
    except:
        print("error: jq is required")
        return False

    try:
        cmd = "echo suricata | xargs > nil" if WIN32 else "echo | xargs > /dev/null 2>&1"
        subprocess.check_call(cmd, shell=True)
    except:
        print("error: xargs is required")
        return False

    return True

def run_test(dirpath, args, cwd, suricata_config):
    with lock:
        if check_args['fail'] == 1:
            raise TerminatePoolError()

    name = os.path.basename(dirpath)

    outdir = os.path.join(dirpath, "output")
    if args.outdir:
        outdir = os.path.join(os.path.realpath(args.outdir), name, "output")

    test_runner = TestRunner(
        cwd, dirpath, outdir, suricata_config, args.verbose, args.force,
        args.quiet)
    try:
        results = test_runner.run(outdir)
        if results["failure"] > 0:
            with lock:
                count_dict["failed"] += 1
                failedLogs.append(dirpath)
        elif results["skipped"] > 0 and results["success"] == 0:
            with lock:
                count_dict["skipped"] += 1
        elif results["success"] > 0:
            with lock:
                count_dict["passed"] += 1
                if args.aggressivecleanup:
                    try:
                        shutil.rmtree(outdir)
                    except Exception as err:
                        print("ERR: Couldn't delete output dir in aggressive cleanup mode")
                        traceback.print_exc()
    except UnsatisfiedRequirementError as ue:
        if not args.quiet:
            print("===> {}: SKIPPED: {}".format(os.path.basename(dirpath), ue))
        with lock:
            count_dict["skipped"] += 1
    except TestError as te:
        print("===> {}: FAILED: {}".format(os.path.basename(dirpath), te))
        check_args_fail()
        with lock:
            count_dict["failed"] += 1
            failedLogs.append(dirpath)
    except Exception as err:
        print("===> {}: FAILED: Unexpected exception: {}".format(os.path.basename(dirpath), err))
        traceback.print_exc()

        # Always terminate the runner on this type of error, as its an error in the framework.
        with lock:
            check_args['fail'] = 1
            count_dict["failed"] += 1
            failedLogs.append(dirpath)
            raise TerminatePoolError()

def run_mp(jobs, tests, dirpath, args, cwd, suricata_config):
    print("Number of concurrent jobs: %d" % jobs)
    pool = mp.Pool(jobs)
    try:
        for dirpath in tests:
            pool.apply_async(run_test, args=(dirpath, args, cwd, suricata_config))
    except TerminatePoolError:
        pool.terminate()
    pool.close()
    pool.join()

def run_single(tests, dirpath, args, cwd, suricata_config):
    try:
        for dirpath in tests:
            run_test(dirpath, args, cwd, suricata_config)
    except TerminatePoolError:
        sys.exit(1)

def build_eve_validator():
    env = os.environ.copy()
    if "CARGO_BUILD_TARGET" in env:
        del env["CARGO_BUILD_TARGET"]
    subprocess.check_call(
            "cargo build --release", cwd=os.path.join(TOPDIR, "eve-validator"),
            shell=True, env=env)

def main():
    global TOPDIR
    global args

    if not check_deps():
        return 1

    parser = argparse.ArgumentParser(description="Verification test runner.")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("--force", dest="force", action="store_true",
                        help="Force running of skipped tests")
    parser.add_argument("--fail", action="store_true",
                        help="Exit on test failure")
    parser.add_argument("--testdir", action="store",
                        help="Runs tests from custom directory")
    parser.add_argument("--exact", dest="exact", action="store_true",
                        help="Use supplied name to make an exact match")
    parser.add_argument("--skip-tests", nargs="?", default=None,
                        help="Skip tests with a given pattern")
    parser.add_argument("--outdir", action="store",
                        help="Outputs to custom directory")
    parser.add_argument("--valgrind", dest="valgrind", action="store_true",
                        help="Run tests in with valgrind")
    parser.add_argument("--self-test", action="store_true",
                        help="Run self tests")
    parser.add_argument("--debug-failed", dest="debugfailed", action="store_true",
                        help="Prints debug output for failed tests")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true",
                        help="Only show failures and end summary")
    parser.add_argument("--aggressive-cleanup", dest="aggressivecleanup", action="store_true",
                        help="Clean up output directories of passing tests")
    parser.add_argument("--no-validation", action="store_true", help="Disable EVE validation")
    parser.add_argument("patterns", nargs="*", default=[])
    if MP:
        parser.add_argument("-j", type=int, default=min(8, mp.cpu_count()),
                        help="Number of jobs to run")
    args = parser.parse_args()

    if args.self_test:
        return unittest.main(argv=[sys.argv[0]])

    TOPDIR = os.path.abspath(os.path.dirname(sys.argv[0]))

    # Get the current working directory, which should be the top
    # suricata source directory.
    cwd = os.getcwd()
    if not (os.path.exists(suricata_yaml) and
            os.path.exists(suricata_bin)):
        print("error: this is not a suricata source directory or " +
              "suricata is not built")
        return 1

    global VALIDATE_EVE
    if not WIN32 and not args.no_validation:
        if not os.path.exists(os.path.join(cwd, "etc", "schema.json")):
            print("Warning: No schema.json to validate eve.")
            VALIDATE_EVE = False
        else:
            try:
                build_eve_validator()
                VALIDATE_EVE = True
            except:
                print("error: Failed to build EVE validator, validation will be disabled")
    else:
        VALIDATE_EVE = False

    skipped = 0
    passed = 0
    failed = 0

    # Create a SuricataConfig object that is passed to all tests.
    suricata_config = SuricataConfig(get_suricata_version())
    suricata_config.valgrind = args.valgrind
    tdir = os.path.join(TOPDIR, "tests")
    if args.testdir:
        tdir = os.path.abspath(args.testdir)
    # First gather the tests so we can run them in alphabetic order.
    tests = []
    for dirpath, dirnames, filenames in os.walk(tdir, followlinks = True):
        # The top directory is not a test...
        if dirpath == os.path.join(TOPDIR, "tests"):
            continue
        if dirpath == tdir:
            continue
        basename = os.path.basename(dirpath)
        if args.skip_tests:
            skip_tests_opt = False
            patterns = args.skip_tests.split(",")
            for pattern in patterns:
                if args.exact:
                    if pattern == basename:
                        skip_tests_opt = True
                        break
                elif basename.find(pattern) > -1:
                    skip_tests_opt = True
                    break
            if skip_tests_opt:
                continue

        # Check if there are sub-test directories
        if "test.yaml" in filenames:
            # gets used by os.walk in this for loop
            dirnames[0:] = []
        else:
            continue

        if not args.patterns:
            tests.append(dirpath)
        else:
            for pattern in args.patterns:
                if args.exact:
                    if pattern == basename:
                        tests.append(dirpath)
                elif basename.find(pattern) > -1:
                    tests.append(dirpath)

    # Sort alphabetically.
    tests.sort()

    if MP and args.j > 1:
        run_mp(args.j, tests, dirpath, args, cwd, suricata_config)
    else:
        run_single(tests, dirpath, args, cwd, suricata_config)

    passed = count_dict["passed"]
    failed = count_dict["failed"]
    skipped = count_dict["skipped"]

    print("")
    print("PASSED:  %d" % (passed))
    print("FAILED:  %d" % (failed))
    print("SKIPPED: %d" % (skipped))

    if args.debugfailed:
        if len(failedLogs) > 0:
            print("")
            print("Failed tests debug output:")
        for dirpath in failedLogs:
            print("- Test %s:" % os.path.basename(dirpath))
            for r, d, f in os.walk(dirpath+"/output"):
                for fname in f:
                    path = os.path.join(r, fname)
                    print("  - %s" % path)
                    try:
                        with open(path, "r") as fcontents:
                            try:
                                buf = fcontents.read()
                                print(buf)
                            except:
                                print("    - [Not dumping file that won't utf-8 decode]")
                    except Exception as err:
                        print("Failed to open %s: %s" % (path, str(err)))

    if failed > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
