Reproducer for lua: ssh.enable_hassh() and ja3.enable_ja3() end with
"return 1" without pushing a result, so the Lua call returns the
function object itself when called with no arguments.

The script requires both calls to return nil.

Ticket: #9084.
