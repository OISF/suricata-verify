Reproducer for lua: LuaStateNeedProto() returns LuaCallbackError's 2
when there is no flow, but callers treat the result as a boolean. With
no flow, ja3.get_tx() takes the "protocol is TLS" branch and reports
"error: no tx available" instead of a protocol/flow error.

The output setup() (no flow/tx) calls ja3.get_tx() and requires the
result to mention the protocol problem.

Ticket: #9062.
