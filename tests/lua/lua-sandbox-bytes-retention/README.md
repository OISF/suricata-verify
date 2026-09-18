Reproducer for lua: security.lua.max-bytes is a per-call budget, not a
memory cap. SCLuaSbUpdateBytesLimit() sets alloc_limit to
alloc_bytes + cfg_limit after every call, so every byte a script retains
(module-level tables, etc) permanently raises the effective cap by that
amount plus the configured budget.

The script retains 10KB per match call with max-bytes=20000. With the
bug every call succeeds (no memory limit error, unbounded retention);
with an absolute cap the script trips the memory limit and the error is
reported.

Ticket: #9053.
