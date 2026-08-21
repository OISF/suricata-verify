# Suricata-Verify Live Tests

This directory contains a harness for tests that run Suricata against live
traffic. A live test runs Suricata in IDS or IPS mode while a real client and
server exchange traffic in an isolated network environment.

## Running Tests

Run all live tests from a built Suricata source directory:

```
sudo ../suricata-verify/live/run.py
```

As with the non-live runner, positional arguments select tests by name. Multiple
patterns may be provided, and `--exact` changes them from substring matches to
exact names. Use `--skip-tests` with a comma-separated list to exclude tests.

```
sudo ../suricata-verify/live/run.py simple-http pcap-ids
sudo ../suricata-verify/live/run.py --exact simple-http-ids
sudo ../suricata-verify/live/run.py --skip-tests=nfq,dpdk
```

## Supported Environments

- tap: Creates a bridge in the DUT namespace so Suricata can passively monitor
  traffic between the client and server namespaces. The Linux bridge acts like
  a span port on a switch. Suricata can attach to its `br0` interface with a
  compatible capture mechanism such as AF_PACKET or libpcap.

- inline: Creates an inline topology in which Suricata forwards all traffic
  between the client and server. This is useful for IPS testing with capture
  mechanisms such as AF_PACKET or DPDK.

- nfq: Creates a routed topology in which NFQUEUE intercepts traffic between
  the client and server.

Each test's `environment` selects its network topology. Its `args` select the
Suricata capture mechanism and run mode, using arguments such as `--pcap=br0`,
`--af-packet`, `--dpdk`, or `-q 0`.

## Linux Network Namespaces

Linux network namespaces provide an isolated network. The runner creates these
namespaces:

- `dut`: The device under test, where Suricata runs.
- `server0`: The server namespace, where applications such as an HTTP server
  run.
- `client0`: The client namespace, where user-controlled scripts run tools such
  as `curl`.

Client and server namespaces are numbered by network. The default topology has
one network (`client0`/`server0`), and there is only ever one `dut` namespace.
Endpoint interfaces are named `client` and `server`. DUT interfaces are named
`client0`/`server0`, `client1`/`server1`, and so on.

## Default Topologies

All three environments share the same default single-network layout: a
`client0` and a `server0` namespace, each wired to the `dut` namespace with a
veth pair. They differ in how the two DUT interfaces are connected to each
other.

### tap

The DUT interfaces are members of a Linux bridge, `br0`, which forwards traffic
on its own. Suricata attaches to `br0` (e.g., with `--pcap=br0` or
`--af-packet=br0`) and passively observes:

```
+------------+     +---------------------+     +------------+
|  client0   |     |         dut         |     |  server0   |
|            |     |                     |     |            |
|   client   |-----| client0     server0 |-----|   server   |
| 10.200.0.2 |     |    |           |    |     | 10.200.0.1 |
+------------+     |    +----br0----+    |     +------------+
                   |          |          |
                   |      Suricata       |
                   +---------------------+
```

### inline

No bridge is created. The client and server can communicate only when Suricata
forwards traffic between the two DUT interfaces, using, for example, AF_PACKET
copy mode or DPDK:

```
+------------+     +---------------------+     +------------+
|  client0   |     |         dut         |     |  server0   |
|            |     |                     |     |            |
|   client   |-----| client0     server0 |-----|   server   |
| 10.200.0.2 |     |    |           |    |     | 10.200.0.1 |
+------------+     |    +--Suricata-+    |     +------------+
                   +---------------------+
```

### nfq

The DUT is a router: it owns an address on each network, the endpoints use it
as their default gateway, and `iptables` queues all forwarded traffic to
NFQUEUE 0, where Suricata (`-q 0`) provides the verdict:

```
+------------+     +-----------------------------+     +------------+
|  client0   |     |             dut             |     |  server0   |
|            |     |                             |     |            |
|   client   |-----| client0             server0 |-----|   server   |
| 10.200.1.2 |     | 10.200.1.254   10.200.0.254 |     | 10.200.0.1 |
+------------+     |      |               |      |     +------------+
                   |      +----NFQUEUE----+      |
                   |       Suricata (-q 0)       |
                   +-----------------------------+
```

The client's default route points at `10.200.1.254`, the server's at
`10.200.0.254`, and the DUT has `ip_forward` enabled.

## Per-test Inline Topologies

Inline tests may replace the default single-network, unbonded, MTU-1500 layout
with a `topology` mapping. A custom topology must contain at least one network,
and every network must specify client and server IPv4 CIDRs in the same subnet.
Omit `bond` and `bond-mode` for an unbonded network. Set `bond: true` to make
both the endpoint and DUT logical interfaces bonds with two veth members. A
bonded network must also set `bond-mode`; there is no default bond mode.
Supported modes are `balance-rr`, `active-backup`, `balance-xor`, `broadcast`,
`802.3ad`, `balance-tlb`, and `balance-alb`. The optional topology MTU defaults
to 1500.

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
`server1` in the DUT. All generated physical member names stay within Linux's
15-character interface-name limit. Custom topologies are rejected for the tap
and NFQ environments.

The example above is the dual-network, dual-bond topology used by the
`afp-ips-bond-two-networks` test. Each `a`/`b` link below is a veth pair that
acts as a bond member. Endpoint members are named `client-a`/`client-b` (and
likewise `server-a`/`server-b`); DUT members are named
`client0-a`/`client0-b`, and so on. Suricata runs inline across each network's
bond pair (e.g., in AF_PACKET copy mode between `client0`/`server0` and between
`client1`/`server1`):

```
+------------+     +---------------------+     +------------+
|  client0   |     |         dut         |     |  server0   |
|            |     |                     |     |            |
|   client   |--a--| client0     server0 |--a--|   server   |
|   (bond)   |--b--| (bond)       (bond) |--b--|   (bond)   |
| 10.200.0.2 |     |    |           |    |     | 10.200.0.1 |
+------------+     |    +--Suricata-+    |     +------------+
                   |                     |
+------------+     |                     |     +------------+
|  client1   |     |                     |     |  server1   |
|            |     |                     |     |            |
|   client   |--a--| client1     server1 |--a--|   server   |
|   (bond)   |--b--| (bond)       (bond) |--b--|   (bond)   |
| 10.200.1.2 |     |    |           |    |     | 10.200.1.1 |
+------------+     |    +--Suricata-+    |     +------------+
                   +---------------------+
```

Omitting `topology` uses the default single-network, unbonded, MTU-1500 layout.

## Test Requirements

Tests can declare required host commands in `test.yaml`. If a required command
is missing, the test is skipped. Tests in the NFQ environment also implicitly
require Suricata's `NFQ` build feature.

```
requires:
  command:
    - podman
    - curl
```

## Suricata Arguments

Tests must provide Suricata command-line arguments with the `args` key in
`test.yaml`, including the capture mechanism and any required run-mode option.
Each entry is parsed using shell syntax after variable substitution. The
supported variables are `SRCDIR`, `TESTDIR`, `TEST_DIR`, `OUTDIR`, and
`OUTPUT_DIR`.

```
args:
  - --pcap=br0
  - --set stream.checksum-validation=no
```

## Life Cycle of a Test

- First, the runner creates the network namespaces and virtual interfaces. In
  the tap environment, it creates a Linux bridge that acts like a switch or
  span port. In the NFQ environment, it configures `iptables` for routing and
  packet interception.

- The optional `before` script performs additional per-test setup. Tests that
  use Podman should build their containers here (e.g., with `podman build`).

- The runner starts Suricata and waits for its "Engine started" message. The
  test fails if Suricata does not become ready.

- The runner starts the optional server script. A server may be Caddy, a Python
  script, or another long-running service. It must remain alive while the client
  runs.

  The server is considered ready after it remains alive for a short grace
  period. The test fails if it exits unexpectedly.

- The runner executes the client script, which drives the test by sending
  traffic to the server. The test fails if the client exits with a nonzero
  status.

- After the client exits, the runner stops the server, sends SIGTERM to
  Suricata, waits for Suricata to exit, and tears down the network environment.

- Finally, the runner performs the configured verification checks.

## Failing a Test

Common failure conditions include:

1. Suricata does not become ready.

2. A setup, server, or client script exits unexpectedly or with a nonzero
   status.

3. A configured verification check fails.
