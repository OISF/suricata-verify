#!/usr/bin/env python3
"""
Generate a PCAP file for testing the error_or option of the absent keyword with base64 transforms.

This creates HTTP POST requests with different base64 payloads:
1. Invalid base64 data (to trigger decode error)
2. Valid base64 containing "malicious"
3. Invalid base64 with "error" as raw text
4. Valid base64 without target content
"""

from scapy.all import *
import base64

def create_http_request(payload):
    """Create an HTTP POST request with the given payload."""
    http_request = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        b"\r\n" +
        payload
    )
    return http_request

def main():
    packets = []

    # Common packet parameters - use different ports for each connection
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.200"
    dst_port = 80

    test_cases = [
        (b"!!!invalid@base64#data$$$", None, "invalid base64"),
        (None, b"This is malicious content", "valid base64 with malicious"),
        (None, b"This is benign content", "valid base64 benign"),
    ]

    for idx, (invalid_payload, valid_payload, desc) in enumerate(test_cases):
        src_port = 12345 + idx  # Different source port for each connection
        seq = 1000
        ack = 2000

        # SYN
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S', seq=seq)
        packets.append(pkt)

        # SYN-ACK
        pkt = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='SA', seq=ack, ack=seq+1)
        packets.append(pkt)

        # ACK
        seq += 1
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A', seq=seq, ack=ack+1)
        packets.append(pkt)
        ack += 1

        # Prepare payload
        if invalid_payload:
            payload = invalid_payload
        else:
            payload = base64.b64encode(valid_payload)

        # HTTP Request
        http_req = create_http_request(payload)
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq, ack=ack)/Raw(load=http_req)
        packets.append(pkt)
        seq += len(http_req)

        # ACK from server
        pkt = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='A', seq=ack, ack=seq)
        packets.append(pkt)

        # FIN from client
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='FA', seq=seq, ack=ack)
        packets.append(pkt)
        seq += 1

        # FIN-ACK from server
        pkt = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='FA', seq=ack, ack=seq)
        packets.append(pkt)
        ack += 1

        # Final ACK from client
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A', seq=seq, ack=ack)
        packets.append(pkt)

    # Write packets to PCAP file
    wrpcap('input.pcap', packets)
    print("Generated input.pcap with HTTP test traffic (separate connections)")
    print(f"Test 1: {test_cases[0][0]}")
    print(f"Test 2: {base64.b64encode(test_cases[1][1])} -> {test_cases[1][1]}")
    print(f"Test 3: {base64.b64encode(test_cases[2][1])} -> {test_cases[2][1]}")

if __name__ == "__main__":
    main()
