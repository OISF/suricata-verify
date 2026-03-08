#!/usr/bin/env python3
"""Generate PCAP for byte_extract test: http_raw_header -> file_data.

Test: Extract Content-Length from response header, use in file_data byte_test.
Response header: "Content-Length: 11" - byte_extract extracts "11" (decimal 11).
Response body: "leetstest" + b"\\x0b\\x00" - after matching "test",
byte_test:2,=,content-length,0,relative,little checks 2-byte little-endian
value 0x000b (11) equals the extracted content-length (11).
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
    b"GET /mybytes.htmeal HTTP/1.1\r\n"
    b"User-Agent: Wintermute\r\n"
    b"\r\n"
)

response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Neuromancer\r\n"
    b"Content-Length: 11\r\n"
    b"\r\n"
    b"leetstest\x0b\x00"
)

pkts = make_tcp_stream(request, response)
wrpcap("test.pcap", pkts)
print("Generated test.pcap for raw_header -> file_data byte_test")
