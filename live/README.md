# Suricata-Verify Live Tests

This directory contains a test harness and tests for live tests. A
live test is where Suricata is running in an IDS or IPS mode
monitoring traffic between a real client and server in an isolated
network environment.

## Supported Modes

- IDS: Runs Suricata in AF_PACKET IDS mode an interface that can see
  traffic between the client and server namespaces. Internally a Linux
  bridge is used, but you can think of it like a span port on a
  switch.

- AFP: Run Suricata in AF-PACKET IPS mode, bridging all traffic
  between the client and server.

- NFQ: Runs Suricata in NFQ mode (`-q 0`) intercepting all traffic
  between the client and server.

## Linux Network Namespaces

Linux network namespaces are use to provide an isolated network, the
name created are:

- dut: The device under test. This is where Suricata runs.
- server: The server namespace. This is where the server application
  like a HTTP server runs.
- client: The client namespace. This is where your user controlled
  script runs which could run `curl`, etc.

## Test Requirements

Tests can declare required host commands in `test.yaml`. If any command
is missing, the test is skipped.

```
requires:
  commands:
    - podman
    - curl
```

## Suricata Arguments

Tests can add extra Suricata command-line arguments with the `args` key in
`test.yaml`. Each entry is parsed as shell-style arguments after variable
substitution. Supported variables are `SRCDIR`, `TESTDIR`, `TEST_DIR`,
`OUTDIR`, and `OUTPUT_DIR`.

```
args:
  - --set stream.checksum-validation=no
```

## Life Cycle of a Test

- First, the environment is brought up. This includes creating the virtual
  interfaces, and the name spaces. In IDS modes a Linux bridge is create as our
  switch/span port. for NFQ, iptables is setup for routing/firewalling.

- Then the `before` script is run. This is where additional per-test setup can
  be done. If Podman is being used, it is recommended to build the containers
  here (eg: `podman build`) so they don't take up time elsewhere.

- Suricata is now started, and we wait for the "Engine started." output. If
  Suricata fails to start, the test fails.

- The server script, if provided is now started. If a server is used, it is
  expected to stay alive for the duration of the test. A server may be something
  like Caddy (http server), or a Python script running a custom server.
  
  If the server stays alive for a short grace period it is considered
  successfully started.
  
  If the server exits with an error before the client is done, the test will be
  considered a fail.

- Then the client is run. This is the driver of a test. It could be a single
  curl command, or a series of tests interacting with the server.
  
  If the client exits non-successful, then the test fails.

- Teardown happens after the client exits: server is stopped (exit code is
  ignored at this point), Suricata is sent a SIGTERM, we wait for Suricata to
  exit then tear down the environment.

- Checks are run.

## Failing a Test

Provided the Suricata starts successfully, as well as the server, there are 2
ways a test can fail:

1. The `client` scripts exist with a non-successul error code.

2. The standard checks on the `eve.json`, etc. fail.
