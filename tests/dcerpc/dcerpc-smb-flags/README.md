Tests the dcerpc.flags keyword on DCE/RPC carried over SMB, per direction.

Reuses the smb-dce_iface capture, a SPOOLSS exchange over SMB. Every DCE/RPC PDU
in it carries pfc_flags 0x03 (PFC_FIRST_FRAG | PFC_LAST_FRAG). The transaction
records pfc_flags per direction: req_flags from the request PDU (matched on
to_server) and resp_flags from the response PDU (matched on to_client).

Request side (to_server): the bind and three request PDUs are matched by value
(decimal and hex) and by bitmask on the individual flag bits, plus a negative
value that must not match.

Response side (to_client): the bind_ack and three response PDUs are matched by
value and by the PFC_LAST_FRAG bit. sid 8 is a regression guard: resp_flags must
hold the pfc_flags byte, not the PDU type. The bind_ack's packet_type is 0x0c;
an earlier bug stored packet_type in resp_flags, which this check would catch by
matching 0x0c. It must stay at zero.
