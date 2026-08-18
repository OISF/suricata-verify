#!/usr/bin/env python3
"""Generate input.pcap with a file that does NOT have MZ header."""

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


def build_fake_pe():
    """Build a file starting with 'ZM' instead of 'MZ'.

    Otherwise has valid PE structure, but windows_pe should reject it
    because the DOS magic is wrong.
    """
    # DOS Header (64 bytes) with wrong magic
    dos = bytearray(64)
    dos[0:2] = b'ZM'  # Wrong magic - not MZ
    struct.pack_into('<I', dos, 60, 64)  # e_lfanew = 64

    # PE Signature (4 bytes)
    pe_sig = b'PE\x00\x00'

    # COFF Header (20 bytes)
    coff = struct.pack('<HHIIIHH',
        0x014C,   # Machine: x86
        1,        # NumberOfSections
        0,        # TimeDateStamp
        0,        # PointerToSymbolTable
        0,        # NumberOfSymbols
        224,      # SizeOfOptionalHeader
        0x0102,   # Characteristics
    )

    # Optional Header PE32 (224 bytes)
    opt = bytearray(224)
    struct.pack_into('<H', opt, 0, 0x10B)     # Magic: PE32
    struct.pack_into('<I', opt, 16, 0x1000)    # AddressOfEntryPoint
    struct.pack_into('<I', opt, 28, 0x1000)    # ImageBase
    struct.pack_into('<I', opt, 32, 0x1000)    # SectionAlignment
    struct.pack_into('<I', opt, 36, 512)       # FileAlignment
    struct.pack_into('<I', opt, 56, 0x2000)    # SizeOfImage
    struct.pack_into('<I', opt, 60, 512)       # SizeOfHeaders
    struct.pack_into('<H', opt, 68, 3)         # Subsystem
    struct.pack_into('<I', opt, 96, 16)        # NumberOfRvaAndSizes

    # Section Header
    sec = bytearray(40)
    sec[0:6] = b'.text\x00'
    struct.pack_into('<I', sec, 8, 0x1000)
    struct.pack_into('<I', sec, 12, 0x1000)
    struct.pack_into('<I', sec, 16, 512)
    struct.pack_into('<I', sec, 20, 512)
    struct.pack_into('<I', sec, 36, 0x60000020)

    headers = bytes(dos) + pe_sig + coff + bytes(opt) + bytes(sec)
    headers = headers.ljust(512, b'\x00')
    text_data = b'\xCC' * 512

    return headers + text_data


def main():
    pe = build_fake_pe()
    req = http_request("192.168.1.100", "/no_mz.exe")
    resp = http_response(pe, "no_mz.exe")
    pkts = build_http_stream("192.168.1.50", "192.168.1.100", 50001, 80, req, resp)
    wrpcap("input.pcap", pkts)
    print(f"Written input.pcap: no-MZ file (starts with ZM), {len(pe)} bytes, {len(pkts)} packets")


if __name__ == "__main__":
    main()
