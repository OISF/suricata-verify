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

- NFQ: Runs Suricata in NFQ mode (`-q 0`) intercepting all traffic
  between the client and server.

- AFP: Run Suricata in AF-PACKET IPS mode, bridging all traffic
  between the client and server.

## Linux Network Namespaces

Linux network namespaces are use to provide an isolated network, the
name created are:

- dut: The device under test. This is where Suricata runs.
- server: The server namespace. This is where the server application
  like a HTTP server runs.
- client: The client namespace. This is where your user controlled
  script runs which could run `curl`, etc.
