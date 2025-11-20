# README

This test verifies Suricata’s ability to expose the **raw packet buffer** to a
Lua script and ensures that Lua-based flow state tracking behaves correctly at
the packet level.

## Purpose
- Confirm that Suricata provides access to the *entire packet buffer* through  
  `needs["packet"] = true`.
- Ensure the Lua script can maintain a flow variable (`cnt`) across packets.
- Validate that the script returns `1` (triggering an alert) on the second packet.

## Test Description
Two synthetic TCP packets are fed into Suricata.  
For each packet:

1. The Lua script retrieves the flow variable `cnt`.
2. It increments the counter on every packet seen.
3. When the counter reaches `2`, the script returns `1` to generate an alert.



## Expected Results
- The Lua script runs once per packet (two packets total).
- `cnt` increments from 1 → 2.
- An alert (`sid:3`) is produced

## Files
- `test.rules` – Rule invoking the Lua script.
- `test.lua` – Lua script requiring the packet buffer.
- `test.yaml` – Expected event counts for packets and alerts.

