# lua-flow-app-proto

Cover test for `flow:app_layer_proto()` on a normal dns flow: it must
return the 5 documented alproto name strings, with the first value being
the flow's app-layer protocol name ("dns").

The ticket's edge (an alproto with no registered name, which must report
"unknown" instead of a nil/empty string) is unreachable via packet-level
reproduction: every alproto the engine can assign to a real flow has a
registered name, so AppProtoToString() never fails. This pins the
documented contract instead. Identical behavior on the unfixed and fixed
trees (contract cover, green on both).
