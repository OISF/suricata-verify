This test verifies Suricata’s handling of HTTP buffers together with a Lua script
that tracks a per-flow counter.

## Purpose
- Ensure Suricata correctly parses two HTTP requests in the PCAP.
- Validate that the Lua script increments a flow variable (`cnt`) per request.
- Confirm that an alert is generated only on the second request.

## Test Description
The PCAP contains two HTTP POST requests on the same TCP flow.
The Lua script:
1. Reads the `cnt` flow variable.
2. Increments it for every request.
3. Returns `1` when `cnt == 2`.

## Expected Results
- 3 HTTP events.
- 1 alert (`sid:1`).

## Files
- `test.rules` – Lua-enabled rule.
- `test1.lua` – Lua script under test.
- `test.yaml` – Expected outputs.
