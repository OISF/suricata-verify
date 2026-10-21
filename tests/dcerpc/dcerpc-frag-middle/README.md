Tests reassembly of DCE/RPC-over-TCP PDUs fragmented over more than two
fragments.

The pcap (see dcerpc_frag_middle_scapy.py) is one connection carrying a
bind/bind_ack exchange followed by an opnum 11 call whose request and response
are each split over three fragments. Per C706, PFC_FIRST_FRAG (0x01) is set
only on the first fragment and PFC_LAST_FRAG (0x02) only on the last, so the
middle fragment has neither bit set.

A middle fragment does not end the PDU. All three fragments share a call id
and must land on one transaction, with the stub data concatenated in wire
order: req.frag_cnt and res.frag_cnt of 3, and a 24 byte request stub.

sid 2 is the regression guard. Treating a fragment without either fragment
bit as complete closes the transaction on the middle fragment, after which the
last fragment opens a transaction of its own carrying only its own stub data.
The response side is affected the same way and is covered by res.frag_cnt.

The response stub content is deliberately not matched, so that this test does
not depend on how the response header is handled (see
dcerpc-response-stub-hdr).

Ticket: https://redmine.openinfosecfoundation.org/issues/9240
