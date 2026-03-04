#!/usr/bin/env python3
"""Generate PCAP for cross-buffer byte_extract test: http.uri -> file_data.

Test: Extract from URI (toserver), use in file_data isdataat.
URI: "/upload/20" - byte_extract extracts "20" after "/upload/".
file_data: request body "data=hello_world_content!" - after "data=",
isdataat:20,relative checks 20+ bytes remain ("hello_world_content!" = 20 bytes).
"""
from scapy.all import IP, TCP, Raw, wrpcap


def make_tcp_stream(req, resp, sport=40001, dport=80):
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
    b"POST /upload/20 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Length: 25\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"\r\n"
    b"data=hello_world_content!"
)

response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 2\r\n"
    b"\r\n"
    b"OK"
)

pkts = make_tcp_stream(request, response)
wrpcap("test.pcap", pkts)
print("Generated test.pcap for URI -> file_data cross-buffer test")
