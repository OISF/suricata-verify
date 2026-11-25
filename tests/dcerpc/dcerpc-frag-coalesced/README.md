Tests that fragment counting is not inflated when a complete non-last DCE/RPC
fragment and the next fragment are delivered to the parser in the same call.

The pcap (see dcerpc_frag_coalesced_scapy.py) is one connection carrying a
bind/bind_ack exchange followed by an opnum 11 call whose request and response
are each split over three fragments. The first and middle fragments of each
side are sent in a single TCP segment, the last fragment in a segment of its
own.

All three fragments of each side must land on one transaction, with the stub
data concatenated in wire order and each fragment counted once: req.frag_cnt
and res.frag_cnt of 3 and a 24 byte request stub. As in dcerpc-frag-middle,
the response stub size is deliberately not checked.

Without bounding the PDU to the header's frag_length, the bytes of the next
fragment are treated as more stub data of the current one, and the still open
transaction has its fragment count incremented a second time.

Ticket: https://redmine.openinfosecfoundation.org/issues/7546
