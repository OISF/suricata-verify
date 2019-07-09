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

  # Test is only for this version. For example, 4.0 would match any 4.0 
  # release, but 4.0.3 would only match 4.0.3.
  version: 4.0

  # Require the presence of specific features.
  features:
    # Restrict the test to builds with HAVE_LUA.
    - HAVE_LUA

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

skip:
  # Skip a test if a feature is present, with a message that is logged.
  - feature: RUST
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

# Execute Suricata with the test parameters this many times. All checks will
# done after each iteration.
count: 10

pre-check: |
  # Some script to run before running checks.
  cp eve.json eve.json.bak

checks:

  # A verification filter that is run over the eve.json. Multiple
  # filters may exist and all must pass for the test to pass.
  - filter:
      # The number of records this filter should match.
	  count: 1
	  
	  # The fields to match on.
	  match:
	    # Example match on event_type:
		event_type: alert
		
		# Example match on array item:
		alert.metadata.tag[0]: "tag1"
		
		# Check that a field exists:
		has-key: alert.rule
		
		# Check that a field does not exist:
		not-has-key: flow
```		

## eve2test

Script to convert eve.json into test.yaml file. This currently implements the
functionality of creating the "checks" block in `test.yaml` from a given `eve.json`. You can add other configuration in the file thus created.

### Usage
```
$ python eve2test.py -h
 usage: eve2test [-h] [--eventtype-only] [--allow-events [ALLOW_EVENTS]]
                  <path-to-eve> <output-path>

  Convert eve.json to test.yaml

  positional arguments:
    <path-to-eve>         Path to eve.json
    <output-path>         Path to the folder where generated test.yaml should be
                          put

  optional arguments:
    -h, --help            show this help message and exit
    --eventtype-only      Create filter blocks based on count of event types only
    --allow-events [ALLOW_EVENTS]
                          Create filter blocks for the specified events
```
