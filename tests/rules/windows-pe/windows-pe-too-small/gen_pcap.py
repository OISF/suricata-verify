#!/usr/bin/env python3
"""Generate input.pcap with a file too small to be a valid PE (< 64 bytes)."""

import struct
from scapy.all import IP, TCP, Raw, Ether, wrpcap

def http_response(body: bytes, filename: str) -> bytes:
    hdr  = f"HTTP/1.1 200 OK\r\n"
    hdr += f"Content-Type: application/octet-stream\r\n"
    hdr += f"Content-Disposition: attachment; filename=\"{filename}\"\r\n"
    hdr += f"Content-Length: {len(body)}\r\n"
    hdr += f"Connection: close\r\n\r\n"
    return hdr.encode() + body

def http_request(host: str, path: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n").encode()

def build_http_stream(client_ip, server_ip, sport, dport,
                      request: bytes, response: bytes):
    pkts = []
    mac_c = "00:11:22:33:44:01"
    mac_s = "00:11:22:33:44:02"
    cseq = 1000
    sseq = 5000
    def pkt(src_ip, dst_ip, sp, dp, flags, seq, ack, payload=b'', src_mac=mac_c, dst_mac=mac_s):
        p = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
        if payload:
            p = p / Raw(load=payload)
        return p
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'S', cseq, 0))
    cseq += 1
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'SA', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))
    sseq += 1
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'A', cseq, sseq))
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'PA', cseq, sseq, request))
    cseq += len(request)
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'A', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))
    seg_size = 1400
    off = 0
    while off < len(response):
        chunk = response[off:off+seg_size]
        pkts.append(pkt(server_ip, client_ip, dport, sport, 'PA', sseq, cseq, chunk, src_mac=mac_s, dst_mac=mac_c))
        sseq += len(chunk)
        pkts.append(pkt(client_ip, server_ip, sport, dport, 'A', cseq, sseq))
        off += seg_size
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'FA', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))
    sseq += 1
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'A', cseq, sseq))
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'FA', cseq, sseq))
    cseq += 1
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'A', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))
    return pkts


def build_tiny_file():
    """Build a 32-byte file that starts with MZ followed by zeros.

    Too small to contain e_lfanew at offset 60, so windows_pe should reject it.
    """
    data = bytearray(32)
    data[0:2] = b'MZ'
    return bytes(data)


def main():
    tiny = build_tiny_file()
    req = http_request("192.168.1.100", "/too_small.exe")
    resp = http_response(tiny, "too_small.exe")
    pkts = build_http_stream("192.168.1.50", "192.168.1.100", 50001, 80, req, resp)
    wrpcap("input.pcap", pkts)
    print(f"Written input.pcap: too-small file, {len(tiny)} bytes, {len(pkts)} packets")


if __name__ == "__main__":
    main()
