Tests the dcerpc.flags keyword over DCE/RPC-over-UDP (connectionless), per
direction.

The pcap (see dcerpc_flags_udp_scapy.py) is one transaction: a REQUEST
(flags1=0x01, flags2=0x02) from client to server and a RESPONSE (flags1=0x03,
flags2=0x04) from server to client. For UDP the flags field is a u16 built as
(flags2 << 8) | flags1 and stored per direction, so req_flags is 0x0201 and
resp_flags is 0x0403.

The rules confirm req_flags matches on to_server and resp_flags on to_client,
that the request flags are not visible on to_client (per-direction isolation),
and that each byte (flags1 low, flags2 high) can be isolated with a bitmask.
