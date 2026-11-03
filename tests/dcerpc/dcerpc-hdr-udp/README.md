Tests the dcerpc.hdr sticky buffer over DCE/RPC-over-UDP (connectionless).

The pcap (see dcerpc_hdr_udp_scapy.py) is a single transaction: a connectionless
REQUEST (ptype 0) from client to server, and a connectionless RESPONSE (ptype 2)
from server to client, sharing the same activity UUID and sequence number.

For UDP the header is stored per direction as udp_req_hdr / udp_resp_hdr, so
dcerpc.hdr exposes the request-side header on to_server and the response-side
header on to_client. The rules confirm each direction matches its own 80-byte
connectionless header, that a request-header pattern does not match on to_client
(and vice versa), and that the whole header is inspectable (a byte at offset 4).
