Tests that dcerpc.ptype can match previously-unhandled connectionless (UDP)
DCERPC PDU types.

The connectionless protocol only creates transactions for request/response;
other PDU types (here: fault and ping) used to be dropped and were therefore
unmatchable. They are now stored in a transaction (no request-response
pairing) so dcerpc.ptype can match on the header PDU type.

The pcap is derived from the dcerpc-udp-scapy fixture: two packets' pkt_type
bytes are overridden (fault=3, ping=1) and the flow is made bidirectional with
plain client/server addressing so the response-side fault is inspected on
to_client.
