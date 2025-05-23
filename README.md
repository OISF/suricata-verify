# Suricata Verification Tests

These are tests that run Suricata with a specific configuration and/or
inputs and verify the outputs.

## Running All Tests

From your Suricata source directory run:

```
../path/to/suricata-verify/run.py
```

Or to run a single test:
```
../path/to/suricata-tests/run.py TEST-NAME
```

## Adding a New Test

- Create a directory that is the name of the new test.

  If you want a test to be run in IPS mode, add `ips` to the test name.
  This will make the `--simulate-ips` command-line argument be passed when
  the test is run.

- Copy a single pcap file into the test directory. It must end in
  ".pcap".

  This is enough for a basic test that will run Suricata over the pcap
  testing for a successful exit code.

- Optional: Create a suricata.yaml in the test directory.

    Its usually OK to just add the bits of YAML required to enable
    features for the test.

	If the test directory does not include a suricata.yaml, the one
    found in your build directory will be used.

- Add any rules required to ${dir}/test.rules.

- Add a *test.yaml* descriptor file to add further control to your
  tests such as restricting features required for the test, and
  validating output.

## Example test.yaml

```
requires:

  # Require a minimum version of Suricata.
  min-version: 8.0.0

  # Require that the Suricata version be less than a version.
  lt-version: 8

  # Test is only for this version. For example, 4.0 would match any 4.0
  # release, but 4.0.3 would only match 4.0.3.
  version: 7.0.6

  # Test is only for the listed OS. For example, the following would make
  # a test run only on Linux.
  os: linux

  # Test is only for the liste architecture. For example, following would
  # make a test run only on x86_64. Other values can be amd64, i386, etc.
  arch: x86_64

  # Require the presence of specific features.
  features:
    # Restrict the test to builds with HAVE_LUA.
    - HAVE_LUA

  # Require that one or more files exist in the Suricata source directory
  files:
	- src/detect-ipaddr.c

  # Don't require a pcap file to be present. By default a test will be skipped
  # if there is no pcap file in the test directory. Not applicable if a
  # command is provided.
  pcap: false

  # Run the script and only continue with the test if the script exists
  # successfully.
  script:
    - command1
    - command2
    - ...

  # Require the output of a Python expression to be true. For example,
  # this will run on all platforms other than win32.
  lambda: "sys.platform != win32"

skip:
  # Skip a test if a feature is present, with a message that is logged.
  - feature: HAVE_LUA
    msg: eve dns v1 not supported by rust

# Add additional arguments to Suricata.
args:
  - --set stream.reassembly.depth=0

# Override the default command. This is also an example of how it can
# be broken up over multiple lines for readability. If providing the command
# all arguments must be provided as part of the command.
command: |
  ${SRCDIR}/src/suricata -T -c ${TEST_DIR}/suricata.yaml -vvv \
      -l ${TEST_DIR}/output --set default-rule-path="${TEST_DIR}"

# Retry a test 3 more times on failure. Some tests are subject to
# timing errors on CI systems and this can help filter out the noise
# of tests that fail in such environments. By default, tests are only
# run once.
retry: 3

# Execute Suricata with the test parameters this many times. All checks will
# done after each iteration.
count: 10

pre-check: |
  # Some script to run before running checks.
  cp eve.json eve.json.bak

# Provide a pcap filename. A falsey value like false or empty is equivalent to setting
# "pcap: false" in the requires section.
pcap: input.pcap

# Test for a specific exit code. By default a test will fail if the
# exit code is anything other than 0, however sometimes we may be
# testing for failure.
exit-code: 1

checks:

  # A verification filter that is run over the eve.json. Multiple
  # filters may exist and all must pass for the test to pass.
  - filter:

      # Requires that apply just to this check. Has all the same options
      # as the test level requires above.
      requires:
        features:
          - HTTP2_DECOMPRESSION

      # The number of records this filter should match.
      count: 1

      # The fields to match on.
      match:
        # Example match on event_type:
        event_type: alert

        # Example match on array item:
        alert.metadata.tag[0]: "tag1"

        # Example match on the length of an array.
        alert.metadata.tag.__len: 3

        # Check that a field exists:
        has-key: alert.rule

        # Check that a field does not exist:
        not-has-key: flow

  - filter:
	  # Use a filename other than eve.json
	  filename: suricata.json
	  count: 1
	  match:
	    # Find a substring in a field
		engine.message.__find: script failed

        # Check if a string starts with an expected value
        engine.message.__startswith: "This is the start of the string"

        # Check if a string ends with an expected value
        engine.message.__endswith: "the end of a string"

        # Check if a string is contained within a JSON list.
        # Eg. "ftp":{"reply":["Opening BINARY mode data connection for temp.txt (1164 bytes).","Transfer complete."], }
        ftp.reply.__contains: 'Transfer complete.'

  - shell:
      # A simple shell check. If the command exits with a non-0 exit code the
      # check will fail. The script is run in the output directory of the
      # test.
      args: grep "GPL ATTACK_RESPONSE" fast.log

  - shell:
      # A shell check that also tests the output of the command.
      args: cat fast.log | wc -l | xargs
      expect: 1

  - file-compare:
      # A check that compares two files
      filename: datasets.csv
      expected: expected/datasets.csv
```

## Adding a new test the automated way: createst

Createst is a script to create a test directory with test.yaml for a given PCAP.
This needs to be run from a valid Suricata source directory.

### Usage
```
usage: createst.py [-h] [--rules <rules>] [--output-path <output-path>]
                   [--eventtype-only] [--allow-events [ALLOW_EVENTS]] [--strictcsums]
                   [--midstream] [--min-version <min-version>] [--version <add-version>]
                   [--cfg <path-to-suricata.yaml>] [--features <features>]
                   <test-name> <pcap-file>

Create tests with a given PCAP. Execute the script from a valid Suricata source
directory.

positional arguments:
  <test-name>           Name of the test folder
  <pcap-file>           Path to the PCAP file

options:
  -h, --help            show this help message and exit
  --rules <rules>       Path to rule file
  --output-path <output-path>
                        Path to the folder where generated test.yaml should be put
  --eventtype-only      Create filter blocks based on event types only
                        This means the subfields of the event in the eve log
                        will not be added to the test.yaml file
  --allow-events [ALLOW_EVENTS]
                        Create filter blocks for the specified events
                        Events must be comma-separated only
                        This means that just the events listed will be checked
                        against in the test
  --strictcsums         Strictly validate checksum
  --midstream           Allow midstream session pickups
  --min-version <min-version>
                        Adds a global minimum required version
  --version <add-version>
                        Adds a global suricata version
  --cfg <path-to-suricata.yaml>
                        Adds a suricata.yaml to the test
  --features <features>
                        Adds specified features
```

### Examples

The only mandatory arguments for ``createst.py`` are the test name and the pcap
file. These examples show how some of the optional arguments can be used.

#### Example 1

Create a Suricata-verify test named ``test-01`` that runs over a pcap file called
``input.pcap`` and that requires strict checksums, filters only on the event-types
and uses no Suricata rules:
```
../suricata-verify/createst.py --strictcsums --eventtype-only test-01 input.pcap
```

#### Example 2

Create a Suricata-verify test named ``test-02`` that runs over a pcap file called
``input.pcap``, only checks for ``http``, ``alert`` and ``flow`` events, and
uses a rules file located in another test in the same suricata-verify folder.
It also doesn't require strict checksums and will run only for versions 6 and
newer:
```
../suricata-verify/createst.py --min-version 6 --allow-events http,alert,flow \
--rules ../suricata-verify/tests/no-payload-output/test.rules test-02 input.pcap
```

#### Add Required Features

```
../suricata-verify/createst.py --features HAVE_LUA
```

```
../suricata-verify/createst.py --features HAVE_LUA,AF_PACKET
```

The features are taken from the `Features:` line in `suricata
--build-info`.
