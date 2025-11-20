# README

This test verifies Lua’s ability to use **flowints** while inspecting the
**HTTP request buffer** provided by Suricata.

## Purpose
- Ensure that Suricata exposes the HTTP request buffer via the
  `http1:request_complete` app-layer event.
- Validate the use of `suricata.flowint` to maintain per-flow integer state across
  multiple HTTP transactions.
- Confirm that the Lua script correctly increments the flowint value and
  triggers an alert when the counter reaches 2.

## Test Description
Two separate HTTP request buffers are sent to Suricata.  
For each request:

1. `cnt = flowintlib.get("cnt")` retrieves a per-flow integer.
2. The Lua script increases the integer on every HTTP request.
3. When the counter becomes `2`, the script returns `1`, which triggers an alert.


This ensures that the Lua `match()` function is invoked once per completed
HTTP request.

## Expected Results
- Three HTTP request and a flow events are processed.
- `cnt` increments from 1 → 2.
- An alert (`sid:1`) is generated **only on the second HTTP request**.
- No alerts should occur on the first request.

## Files
- `test.rules` – Rule invoking the Lua script on HTTP request completion.
- `test.lua` – Lua script using flowints.
- `test.yaml` – Expected HTTP event count and alert count.


