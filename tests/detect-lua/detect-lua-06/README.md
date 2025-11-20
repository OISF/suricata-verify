# README

This test verifies Lua’s use of **flowints** with **HTTP request buffers**,
specifically testing the `:decr()` method.

## Purpose
- Validate that `suricata.flowint` supports decrementing a per-flow counter using `:decr()`.
- Ensure Lua can initialize a flowint to a custom value if it does not exist.
- Confirm that the alert triggers when the flowint reaches zero.

## Test Description
Suricata processes two HTTP request buffers.  
For each request:

1. `cnt = flowintlib.get("cnt")` retrieves the per-flow counter.
2. If the counter does not exist (`nil`), it is initialized to `2`.
3. `a = cnt:decr()` decrements the counter and returns the new value.
4. When `a` equals `0`, the script triggers an alert by returning `1`.


## Expected Results
- Three HTTP request and one flow events are generated.
- `cnt` behaves as follows:  
  - First request: initialized to 2 → decremented to 1  
  - Second request: decremented to 0 → triggers alert
- Exactly **one alert (sid:1)** should be produced.

## Files
- `test.rules` – Rule invoking the Lua script on HTTP request completion.
- `test.lua` – Lua script using `cnt:decr()`.
- `test.yaml` – Validates number of HTTP events and alert count.


