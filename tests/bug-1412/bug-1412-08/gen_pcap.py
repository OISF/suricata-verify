#!/usr/bin/env python3
"""Generate PCAP for bidirectional cross-buffer byte_extract + byte_math test.

Test: Extract from http.uri (toserver), compute with byte_math, then use
result via isdataat in http.stat_msg (toclient).

URI is "/math/03/02":
  - byte_extract:2,0,a_val,relative,string,dec  -> reads "03" = 3
  - content:"/"; distance:0  -> advances past the "/"
  - byte_math:bytes 2, offset 0, oper +, rvalue a_val, result sum_val,
    relative, string, dec  -> reads "02" = 2, computes 2 + 3 = 5

Response status message is "OK" (2 bytes).
After matching "O", position is 1; only 1 byte remains ("K").
isdataat:!sum_val,relative -> NOT 5 bytes remaining at pos 1 -> true -> alert.
"""
from scapy.all import IP, TCP, Raw, wrpcap


def make_tcp_stream(req, resp, sport=40004, dport=80):
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.1"
    syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=100)
    synack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101)
    ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=201)
    req_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=101, ack=201) / Raw(load=req)
    resp_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=201, ack=101 + len(req)) / Raw(load=resp)
    fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=101 + len(req), ack=201 + len(resp))
    finack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="FA", seq=201 + len(resp), ack=102 + len(req))
    lastack = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=102 + len(req), ack=202 + len(resp))
    return [syn, synack, ack, req_pkt, resp_pkt, fin, finack, lastack]


request = (
    b"GET /math/03/02 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"\r\n"
)

response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 4\r\n"
    b"\r\n"
    b"done"
)

pkts = make_tcp_stream(request, response)
wrpcap("test.pcap", pkts)
print("Generated test.pcap for bidirectional byte_extract + byte_math uri(toserver) -> stat_msg(toclient) test")
