Tests the dcerpc.flags keyword over DCE/RPC-over-TCP, per direction.

The flags field holds the connection-oriented pfc_flags of the transaction, and
is stored per direction: the request/bind side (matched on to_server) and the
response/bind_ack side (matched on to_client). In this flow the request PDU has
pfc_flags 0x83 while the bind, bind_ack and response PDUs have 0x03.

The rules confirm the request-side value (0x83) matches only on to_server, the
response-side value (0x03) matches on to_client, that the request's 0x83 is not
visible on to_client (per-direction isolation), and that a bitmask works on a
given direction. Values use the DetectUint integer syntax (hexadecimal, bitmask).
