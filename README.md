# Suricata Integration Tests

## Running All Tests

From your Suricata source directory run:

```
../path/to/suricata-tests/run.sh
```

Or to run a single test:
```
../path/to/suricata-tests/run.sh TEST-NAME
```

## Adding a New Test

- Create a directory that is the name of the new test.

- Copy a pcap file to ${dir}/input.pcap.

- Create ${dir}/suricata.yaml.

    Note: You may want to add something like:
    ```
    include: ../etc/suricata-3.1.2
    ```
    to the top and then just make the necessary overrides in the tests
    suricata.yaml.

- Add any rules required to ${dir}/test.rules.

- Add the expected output to ${dir}/expected. This might most easily
  be done by running the test then copying the desired files in the
  output directory to the expected directory (after verification).
