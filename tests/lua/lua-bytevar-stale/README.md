Reproducer for lua/bytevar: value() reads det_ctx->byte_values[id]
directly. The array is SCMalloc'd and never zeroed, has no validity
check, and the slot is not cleared per packet, so a script reading a
variable whose extractor did not run for the current packet observes
uninitialized heap data (ASAN: 0xbe... fill) or a stale value from an
earlier packet.

The rule extracts 4 bytes from dns.query and reads the slot from a
packet phase lua keyword, which runs before the current tx's extractor.
Every call must observe an unset value; with the bug the first call
sees uninitialized data and all later calls see the previous packet's
value (only the first call alerts).

Ticket: #9057.
