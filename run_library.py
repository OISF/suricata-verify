#! /usr/bin/env python3
"""
Script to wrap suricata-verify within unitttest and run tests in library mode.

:Copyright:
    Copyright 2022 VMWare.  All Rights Reserved.
"""
import argparse
import glob
import os
import re
import run
import sys
import unittest

from pathlib import Path
from run import get_suricata_version, rule_is_version_compatible, FileCompareCheck, FilterCheck, \
                ShellCheck, StatsCheck, SuricataConfig, TestError, TestRunner, \
                UnsatisfiedRequirementError


def handle_exceptions(func):
    def applicator(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except TestError as te:
            print("\n===> {}: Sub test #{}: FAIL : {}".format(kwargs["test_name"],
                  kwargs["test_num"], te))
            kwargs["count"]["failure"] += 1
        except UnsatisfiedRequirementError:
            kwargs["count"]["skipped"] += 1
        else:
            if result:
              kwargs["count"]["success"] += 1
            else:
              print("\n===> {}: Sub test #{}: FAIL : {}".format(kwargs["test_name"],
                    kwargs["test_num"], kwargs["check"]["args"]))
              kwargs["count"]["failure"] += 1
        return kwargs["count"]
    return applicator

class TestRunnerWrapper(TestRunner):
    """Wrapper around run.TestRunner."""
    def __init__(self, cwd, directory, output, suricata_config):
        super().__init__(cwd, directory, output, suricata_config, False, False, True)

    def default_args(self):
        cwd = Path(self.cwd)
        args = [str(cwd / "examples/suricata_lib/suricata_client")]

        # Load args from config file.
        if "args" in self.config:
            if not isinstance(self.config["args"], list):
                raise TestError("Arguments need to be provided in a list")
            for arg in self.config["args"]:
                # Bypass runmodes.
                if "runmode" in arg:
                    continue

                args += re.split("\s", arg)

        # Classification and reference configs.
        cwd_parent = cwd.parent
        classification_config = next(cwd_parent.glob("**/classification.config"), None)
        if classification_config:
            args += ["--set", "classification-file=%s" % classification_config]

        reference_config = next(cwd_parent.glob("**/reference.config"), None)
        if reference_config:
            args += ["--set", "reference-config-file=%s" % reference_config]

        # Add other fixed arguments.
        args += ["--init-errors-fatal", "-l", self.output, "-c", self.get_suricata_yaml_path()]

        if "ips" in self.name:
            args.append("--simulate-ips")

        # Find rules (only pick the first one).
        rules = glob.glob(os.path.join(self.directory, "*.rules"))
        if not rules:
            args.append("--disable-detection")
        elif len(rules) == 1:
            rulefile = rules[0]
            if rule_is_version_compatible(os.path.basename(rulefile), self.suricata_config.version):
                args += ["-S", rulefile]
            else:
                args.append("--disable-detection")
        else:
            raise TestError("More than 1 rule file found")

        # Find pcaps (pick only one prioritizing pcaps over pcapngs and stream files).
        if "pcap" in self.config:
            args += [os.path.realpath(os.path.join(self.directory, self.config["pcap"]))]
        else:
            pcaps = glob.glob(os.path.join(self.directory, "*.pcap"))
            pcaps += glob.glob(os.path.join(self.directory, "*.pcapng"))
            if len(pcaps) > 1:
                raise TestError("More than 1 pcap file found")
            if pcaps:
                args += [pcaps[0]]
            else:
                # Check for stream files.
                pcaps += glob.glob(os.path.join(self.directory, "*.stream"))
                if pcaps:
                    args += ["-m", "stream"]
                    args += [pcaps[0]]

        return args

    def check(self):
        pdir = os.getcwd()
        os.chdir(self.output)
        count = {"success": 0,
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
                            func = getattr(self, "perform_{}_checks".format(key.replace("-", "_")))
                            func(check=check[key], count=count, test_num=check_count + 1,
                                 test_name=os.path.basename(self.directory))
                        else:
                            print("FAIL: Unknown check type: ", key)
        finally:
            os.chdir(pdir)

        if count["failure"]:
            raise TestError
        elif count["skipped"] and not count["success"]:
            raise UnsatisfiedRequirementError

        return count

    def run(self):
        """Run the inner test."""
        super().run(self.output)

    @handle_exceptions
    def perform_filter_checks(self, check, count, test_num, test_name):
        # Remove some unsupported fields in library mode.
        # `pcap_cnt`.
        if "pcap_cnt" in check["match"]:
            del check["match"]["pcap_cnt"]

        # `tunnel.dest_port`.
        if "tunnel.dest_port" in check["match"]:
            del check["match"]["tunnel.dest_port"]

        # `has-key: community_id`.
        if "has-key" in check["match"] and check["match"]["has-key"] == "community_id":
            del check["match"]["has-key"]

        return FilterCheck(check, self.output, self.suricata_config).run()

    @handle_exceptions
    def perform_shell_checks(self, check, count, test_num, test_name):
        # Bypass checks on 'fast.log' as it is not generated in library mode.
        if "fast.log" in check["args"]:
            return True

        return ShellCheck(check, self.build_env(), self.suricata_config).run()

    @handle_exceptions
    def perform_stats_checks(self, check, count, test_num, test_name):
        return StatsCheck(check, self.output).run()

    @handle_exceptions
    def perform_file_compare_checks(self, check, count, test_num, test_name):
        return FileCompareCheck(check, self.directory).run()

class SuricataVerifyTest(unittest.TestCase):
    """
    Class representing a single suricata-verify test.

    Each `SuricataVerifyTest` instance contains a `TestRunnerWrapper` object whith the actual test
    logic.
    """
    def __init__(self, cwd, directory, output, suricata_config):
        """
        Initialize the inner `TestRunnerWrapper` object.

        :param str cwd: Current working directory.
        :param str directory: Path to the test directory.
        :param str output: Path to the logging output directory.
        :param SuricataConfig suricata_config: Suricata configuration object.
        """
        super().__init__()
        self._test_runner = TestRunnerWrapper(cwd, directory, output, suricata_config)

    def runTest(self):
        """Run a single test."""
        try:
            self._test_runner.run()
        except TestError as te:
            self.fail("{}: FAILED".format(os.path.basename(self._test_runner.directory)))
        except UnsatisfiedRequirementError as ue:
            self.skipTest("{}: SKIPPED".format(os.path.basename(self._test_runner.directory)))

    def shortDescription(self):
        """Override the description to print the name of the running test."""
        return os.path.basename(self._test_runner.directory)

def suite(args):
    """Create the testsuite."""
    suite = unittest.TestSuite()

    # Load tests to skip.
    if args.exclude_file:
        with open(args.exclude_file, "r") as fd:
            excluded = fd.readline().strip()

    # Load tests.
    topdir = Path(__file__).absolute().parent

    # Get the current working directory.
    cwd = Path().cwd()
    if args.cwd:
        cwd = Path(args.cwd) if Path(args.cwd).is_absolute() else Path(cwd, args.cwd)

    suricata_yaml = cwd / run.suricata_yaml
    suricata_bin = cwd / run.suricata_bin
    if not (suricata_bin.exists() and suricata_yaml.exists()):
        print("This is not a suricata source directory or suricata is not built")
        sys.exit(1)

    # Override the globals in run.py.
    run.suricata_yaml = str(suricata_yaml)
    run.suricata_bin = str(suricata_bin)

    # Create a SuricataConfig object that is passed to all tests.
    suricata_config = SuricataConfig(get_suricata_version())
    suricata_config.valgrind = None
    suricata_config.features.add("LIBRARY")
    test_dir = topdir / "tests"

    # First gather the tests so we can run them in alphabetic order.
    tests = []
    for path in test_dir.glob('**/'):
        # Ignore directories that do not contain a 'test.yaml'.
        if not (path / "test.yaml").exists():
            continue

        # Skip test, if needed.
        if args.exclude_file:
            skip_test = False
            patterns = excluded.split(",")
            for pattern in patterns:
                if path.name.find(pattern) > -1:
                    skip_test = True
                    break
            if skip_test:
                continue

        if not args.patterns:
            tests.append(path)
        else:
            for pattern in args.patterns:
                if pattern == path.name:
                    tests.append(path)

    # Sort alphabetically and create the suite.
    tests.sort()
    for dirpath in tests:
        outdir = dirpath / "output"
        suite.addTest(SuricataVerifyTest(str(cwd), str(dirpath), str(outdir), suricata_config))

    return suite

def main():
    parser = argparse.ArgumentParser(description="Verification test runner.")
    parser.add_argument("patterns", nargs="*", default=[])
    parser.add_argument("-c", nargs="?", default="suricata_library.yaml",
                        help="Path to the Suricata yaml.")
    parser.add_argument("--cwd", nargs="?", default=None,
                        help="Path to the directory used as current working directory.")
    parser.add_argument("--exclude-file", nargs="?", default=None,
                        help="Path to the file containing tests to skip.")
    args = parser.parse_args()

    runner = unittest.TextTestRunner()

    sys.exit(not runner.run(suite(args)).wasSuccessful())

if __name__ == "__main__":
    main()
