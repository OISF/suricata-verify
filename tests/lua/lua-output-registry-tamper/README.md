Reproducer for lua: in unsandboxed states the Lua registry is
script-writable and stores the engine context (packet, flow, tx,
det_ctx, ...) as bare lightuserdata. A script can move one context
pointer into the tx key; the transaction libraries then cast it to a
transaction and dereference the wrong struct (SIGSEGV).

The output script retypes the per-event registry entries with another
context pointer and calls dns.get_tx():rrname(). It must survive to
deinit.

Ticket: #9064.
