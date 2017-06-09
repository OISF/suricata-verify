#! /usr/bin/env python2

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

def pipe_reader(fileobj, output=None, verbose=False):
    for line in fileobj:
        if output:
            output.write(line)
        if verbose:
            print(line.strip())

class TestRunner:

    def __init__(self, directory, verbose=False):
        self.directory = directory
        self.verbose = verbose
        self.output = os.path.join(self.directory, "output")

        # The name is just the directory name.
        self.name = os.path.basename(self.directory)

        # List of thread readers.
        self.readers = []

    def run(self):

        sys.stdout.write("===> %s: " % os.path.basename(self.directory))
        sys.stdout.flush()

        args = []
        if os.path.exists(os.path.join(self.directory, "run.sh")):
            args.append(os.path.join(self.directory, "run.sh"))
        else:
            args += self.default_args()

        env = {
            "TZ": "UTC",
            "TEST_DIR": self.directory,
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
            args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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
            print("OK (no check script)")
            return True
        r = subprocess.call(["./check.sh"], cwd=self.directory)
        if r != 0:
            print("FAILED: verification failed")
            return False
        print("OK")
        return True
        
    def default_args(self):
        args = ["./src/suricata",
                "--set", "classification-file=./classification.config",
                "--set", "reference-config-file=./reference.config",
                "--init-errors-fatal",
                "-l", self.output,
        ]

        if "ips" in self.name:
            args.append("--simulate-ips")

        if os.path.exists(os.path.join(self.directory, "suricata.yaml")):
            args += ["-c", os.path.join(self.directory, "suricata.yaml")]
        else:
            args += ["-c", "./suricata.yaml"]

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

def check_for_lua():
    output = subprocess.check_output(["./src/suricata", "--build-info"])
    if output.find("HAVE_LUA") > -1:
        return True
    return False

def check_skip(directory):
    if os.path.exists(os.path.join(directory, "skip")):
        return (True, None)

    if os.path.exists(os.path.join(directory, "skip.sh")):
        rc = subprocess.call([
            "/bin/sh", os.path.join(directory, "skip.sh")])
        if rc == 0:
            return True, None

    if directory.find("lua") > -1:
        if not check_for_lua():
            return (True, "lua not available")

    return (False, None)

def main():

    parser = argparse.ArgumentParser(description="Verification test runner.")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("--force", dest="force", action="store_true",
                        help="Force running of skipped tests")
    parser.add_argument("--fail", action="store_true",
                        help="Exit on test failure")
    parser.add_argument("patterns", nargs="*", default=[])
    args = parser.parse_args()

    topdir = os.path.dirname(sys.argv[0])
    
    skipped = 0
    passed = 0
    failed = 0

    for dirpath, dirnames, filenames in os.walk(topdir):

        # The top directory is not a test...
        if dirpath == topdir:
            dirnames.remove(".git")
            dirnames.remove("etc")
            continue

        # We only want to go one level deep.
        dirnames[0:] = []

        name = os.path.basename(dirpath)

        do_test = False
        if not args.patterns:
            if args.force:
                do_test = True
            else:
                skip, reason = check_skip(dirpath)
                if skip:
                    skipped += 1
                    if reason:
                        print("===> %s: SKIPPED: %s" % (name, reason))
                    else:
                        print("===> %s: SKIPPED" % (name))
                else:
                    do_test = True
        else:
            # If a test matches a pattern, we do not skip it.
            for pattern in args.patterns:
                if name.find(pattern) > -1:
                    skip, reason = check_skip(dirpath)
                    if skip:
                        skipped += 1
                        if reason:
                            print("===> %s: SKIPPED: %s" % (name, reason))
                        else:
                            print("===> %s: SKIPPED" % (name))
                    else:
                        do_test = True
                    break

        if do_test:
            test_runner = TestRunner(dirpath, args.verbose)
            try:
                success = test_runner.run()
            except Exception as err:
                print("FAIL: exception: %s" % (str(err)))
                success = False
            if success:
                passed += 1
            else:
                if args.fail:
                    return 1
                failed += 1

    print("")
    print("PASSED:  %d" % (passed))
    print("FAILED:  %d" % (failed))
    print("SKIPPED: %d" % (skipped))

    if failed > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
