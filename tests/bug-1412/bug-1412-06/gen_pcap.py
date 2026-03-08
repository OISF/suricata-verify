#!/usr/bin/env python3
"""Generate PCAP for bidirectional cross-buffer byte_extract test.

Test: Extract from http.request_body (toserver) -> byte_test in file_data (toclient).
POST body contains "size=07&padding=extra" -> byte_extract extracts "07" (decimal 7).
Response body contains "RESULT\x08end" -> byte_test: byte at offset 0
relative to after "RESULT" is > 7 (0x08 = 8 > 7 = true -> alert).
"""
from scapy.all import IP, TCP, Raw, wrpcap


def make_tcp_stream(req, resp, sport=40002, dport=80):
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


post_body = b"size=07&padding=extra"

# POST request with body containing "size=07"
request = (
    b"POST /submit HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: " + str(len(post_body)).encode() + b"\r\n"
    b"\r\n"
) + post_body

# Response body: "RESULT" followed by byte 0x08
response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 10\r\n"
    b"\r\n"
    b"RESULT\x08end"
)

pkts = make_tcp_stream(request, response)
wrpcap("test.pcap", pkts)
print("Generated test.pcap for bidirectional request_body(toserver) -> file_data(toclient) test")
