# lua-file-get-txid

Cover test for `file:tx_id()` in a file output context (the lua output
script with `type = "file"`). Every file log callback (LuaFileLogger)
sets the tx registry entry (the file's transaction) before the script's
log() runs, so file:tx_id() must return the tx id of the file's
transaction (0 for the first http transaction), not a "no tx available"
error.

The ticket's edge (a file context without a tx, which must surface as
the "error: no tx available" message rather than a stale/absent tx) is
unreachable via packet-level reproduction: file contexts always carry
the file's transaction. This pins the documented contract instead.
Identical behavior on the unfixed and fixed trees (contract cover, green
on both).
