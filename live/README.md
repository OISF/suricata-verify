# Suricata-Verify Live Tests

This directory contains a test harness and tests for live tests. A
live test is where Suricata is running in an IDS or IPS mode
monitoring traffic between a real client and server in an isolated
network environment.

## Supported Environments

- tap: Creates a bridge in the DUT namespace so Suricata can monitor traffic
  between the client and server namespaces. Internally a Linux bridge is used,
  but you can think of it like a span port on a switch.

- inline: Creates an inline topology, Suricata bridging all traffic between the
  client and server.

- nfq: Creates an NFQUEUE routed topology, intercepting all traffic between the
  client and server.

The test's `environment` selects the network topology. The test's `args`
select the Suricata capture/runmode, such as `--pcap=br0`, `--af-packet`,
`--dpdk`, or `-q 0`. This allows a DPDK virtual PMD to run inside a tap or
inline topology.

## Linux Network Namespaces

Linux network namespaces are use to provide an isolated network, the
name created are:

- dut: The device under test. This is where Suricata runs.
- server0: The server namespace. This is where the server application
  like a HTTP server runs.
- client0: The client namespace. This is where your user controlled
  script runs which could run `curl`, etc.

The client and server namespaces are numbered by network. The default topology
has one network (`client0`/`server0`) and there is only ever one `dut`.
Endpoint interfaces are named `client` and `server`. DUT interfaces are named
`client0`/`server0`, `client1`/`server1`, and so on.

## Per-test Inline Topologies

Inline tests may replace the default one-network, unbonded, MTU-1500 layout
with a `topology` mapping. Custom topologies require at least one network
entry. Every entry has explicit client and server IPv4 CIDRs in the same
subnet. Set `bond: true` to make both endpoint and DUT logical interfaces
bonds with two veth members. A bonded network must also set `bond-mode`; there
is no default bond mode. Supported modes are `balance-rr`, `active-backup`,
`balance-xor`, `broadcast`, `802.3ad`, `balance-tlb`, and `balance-alb`. The
optional topology MTU defaults to 1500.

```
environment: inline

topology:
  mtu: 9000
  networks:
    - client: 10.200.0.2/24
      server: 10.200.0.1/24
      bond: true
      bond-mode: balance-rr
    - client: 10.200.1.2/24
      server: 10.200.1.1/24
      bond: true
      bond-mode: balance-rr
```

This creates endpoint namespaces `client0`, `server0`, `client1`, and
`server1`, plus `dut`. Endpoint scripts continue to use logical interfaces
named `client` and `server`; Suricata uses `client0`, `server0`, `client1`, and
`server1` in the DUT. All generated physical-member names stay within Linux's
15-character interface-name limit. Custom topologies are rejected for the tap
and NFQ environments.

Omitting `topology` retains the original single-network, unbonded, MTU-1500
behavior used by existing tests and the manual CLI.

## Test Requirements

Tests can declare required host commands in `test.yaml`. If any command
is missing, the test is skipped. Tests run in the NFQ environment also
implicitly require Suricata's `NFQ` build feature.

```
requires:
  command:
    - podman
    - curl
```

## Suricata Arguments

Tests must provide Suricata command-line arguments with the `args` key in
`test.yaml`, including the capture/runmode argument. Each entry is parsed as
shell-style arguments after variable substitution. Supported variables are
`SRCDIR`, `TESTDIR`, `TEST_DIR`, `OUTDIR`, and `OUTPUT_DIR`.

```
args:
  - --pcap=br0
  - --set stream.checksum-validation=no
```

## Life Cycle of a Test

- First, the environment is brought up. This includes creating the virtual
  interfaces, and the name spaces. In the tap environment a Linux bridge is
  create as our switch/span port. for NFQ, iptables is setup for
  routing/firewalling.

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
