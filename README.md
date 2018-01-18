# Suricata Verification Tests

These are tests that run Suricata with a specific configuration and/or
inputs and verify the outputs.

## Running All Tests

From your Suricata source directory run:

```
../path/to/suricata-verify/run.sh
```

Or to run a single test:
```
../path/to/suricata-tests/run.sh TEST-NAME
```

## Adding a New Test

- Create a directory that is the name of the new test.

- Copy a single pcap file into the test directory. It must end in
  ".pcap" or ".pcapng".

  This is enough for a basic test that will run Suricata over the pcap
  testing for a successful exit code.

- Optional: Create a suricata.yaml in the test directory.

    Note: You may want to add something like:
    ```
    include: ../../etc/suricata-4.0.3.yaml
    ```
    to the top and then just make the necessary overrides in the tests
    suricata.yaml.

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
  min-version: 4.1.0

  # Require the presence of specific features.
  features:
    # Restrict the test to builds with HAVE_LUA.
    - HAVE_LUA

  # Don't require a pcap file to be present. By default a test will be skipped
  # if there is no pcap file in the test directory. Not applicable if a
  # command is provided.
  pcap: false

# Add additional arguments to Suricata.
args:
  - --set stream.reassembly.depth=0

# Override the default command. This is also an example of how it can
# be broken up over multiple lines for readability. If providing the command
# all arguments must be provided as part of the command.
command: |
  ${SRCDIR}/src/suricata -T -c ${TEST_DIR}/suricata.yaml -vvv \
      -l ${TEST_DIR}/output --set default-rule-path="${TEST_DIR}"

# Execute Suricata with the test parameters this many times. All checks will
# done after each iteration.
count: 10
