Reproducer for lua/luaxform: script-supplied return length is not
validated against the real Lua string length, leading to a heap OOB read
in InspectionBufferCopy.

The transform returns a 1 byte string with a claimed length of 100000.
With the bug the inspection buffer is replaced by 100000 bytes (heap
garbage past the Lua string); the content match on the original URI then
fails (or the engine crashes under ASAN). With the length validated and
the copy skipped the original buffer survives and the rule alerts.

Ticket: #9049.
