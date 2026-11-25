Tests that DCE/RPC-over-TCP PDUs consisting of the common header only, with a
frag_length of 16, are skipped without a parser error.

The pcap (see dcerpc_header_only_pdu_scapy.py) has two connections, each with
a bind/bind_ack exchange, a header-only REQUEST and RESPONSE with call id 3,
and an opnum 11 call with call id 2 and 8 bytes of request stub data. In the
first connection every PDU is sent in its own segment. In the second, each
header-only PDU shares a segment with the call id 2 PDU that follows it, so
both reach the parser in the same call.

A header-only PDU has no body to parse. Passing the bytes after its header to
the REQUEST or RESPONSE handling treats either nothing or the next PDU as its
body, and the parser returns an error, after which the rest of the connection
is not parsed. Each connection must instead log the call id 2 transaction
with its stub data, with no DCE/RPC parser error.

The response stub size is deliberately not checked, as in dcerpc-frag-middle.

Ticket: https://redmine.openinfosecfoundation.org/issues/7546
