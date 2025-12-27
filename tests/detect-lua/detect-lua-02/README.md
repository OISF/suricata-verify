This test verifies Suricata’s handling of the **payload buffer** when used
together with a Lua script that tracks a per-flow counter.

## Purpose
- Confirm that Suricata exposes the TCP payload to the Lua script (`needs["payload"] = true`).
- Validate that the Lua script increments a flow variable (`cnt`) every time the payload is inspected.
- Ensure an alert is generated on the second invocation of the script.

## Test Description
Two HTTP POST requests are provided as raw TCP payload data.  
The Lua script:

1. Retrieves the per-flow variable `cnt`.
2. Increments it for each payload the engine processes.
3. Returns `1` (triggering the rule alert) when `cnt == 2`.

## Expected Results
- The script should be invoked twice (once per payload buffer).
- One alert (`sid:2`) should be produced on the second invocation.

## Files
- `test.rules` – Rule invoking the Lua script.
- `test.lua` – Lua script using the payload buffer.
- `test.yaml` – Expected results and output checks.
