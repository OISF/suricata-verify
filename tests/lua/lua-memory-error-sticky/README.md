Reproducer for lua: memory_limit_error is set by the sandbox allocator
but never cleared, so once a script trips the memory limit every later
error in that state is classified as a memory limit error.

The script trips the limit on the first match call, then raises a plain
script error. With the bug stats.detect.lua.memory_limit_errors counts
all calls and the real "generic failure" text never reaches the log.
With the flag cleared per call the second and later errors are counted
as generic script errors and logged with their own text.

Ticket: #9071.
