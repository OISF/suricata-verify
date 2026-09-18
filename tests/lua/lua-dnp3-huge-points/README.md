Reproducer for lua/dnp3: dnp3.get_tx() expands the whole transaction
into Lua tables. A message with enough points (max-points raised above
the sandbox max-bytes budget) makes the call fail with a memory limit
error, and DetectLuaRunMatch returns 0, so the lua keyword and the rule
silently do not match.

The test requires the transaction to be materialized within the budget
(no memory limit errors, the points are visible) instead of silently
bypassing the rule.

Ticket: #9068.
