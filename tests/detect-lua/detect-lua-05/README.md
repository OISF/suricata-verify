This test verifies Lua’s use of **flowints** in combination with the
**HTTP request buffer** exposed by Suricata.

## Purpose
- Confirm that `suricata.flowint` supports the `:incr()` convenience method.
- Validate that per-flow integer state is incremented automatically and persists
  across multiple HTTP request events.
- Ensure that the alert is triggered when the flowint reaches a value of `2`.

## Test Description
Suricata processes two HTTP request buffers.  
For each request:

1. `cnt = flowintlib.get("cnt")` retrieves the per-flow counter.
2. `a = cnt:incr()` increments the counter and returns the new value.
3. When `a` equals `2`, the script triggers an alert by returning `1`.


This ensures the Lua `match()` function is executed once for each completed
HTTP request.

## Expected Results
- Three HTTP request and one flow events are generated.
- `cnt` increments as:  
  - First request: 1  
  - Second request: 2 (triggers alert)
- Exactly **one alert (sid:5)** should be produced.

## Files
- `test.rules` – Rule invoking the Lua script on HTTP request completion.
- `test.lua` – Lua script using `cnt:incr()`.
- `test.yaml` – Validates number of HTTP events and alert count.


