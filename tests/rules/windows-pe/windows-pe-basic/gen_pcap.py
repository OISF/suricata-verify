#!/usr/bin/env python3
"""Generate a PCAP with five PE files served over HTTP.

All PEs are x86 (0x014c), PE32 (magic 0x10b), 1 section (.text),
entry_point=0x1000, subsystem=3 (Console), characteristics=0x0102,
dll_characteristics=0x8500, size_of_headers=512, checksum=0,
num_imports=0, num_exports=0.

SizeOfImage varies per PE: 512, 1024, 512, 4096, 2048.
"""

import struct
from scapy.all import IP, TCP, Raw, Ether, wrpcap


def build_pe(size_of_image: int) -> bytes:
    """Return bytes of a minimal PE32 with one .text section."""

    PE_OFFSET       = 64
    COFF_OFFSET     = PE_OFFSET + 4
    OPT_OFFSET      = COFF_OFFSET + 20
    OPT_SIZE        = 224
    NUM_SECTIONS    = 1
    SECT_HDR_OFFSET = OPT_OFFSET + OPT_SIZE
    SECT_HDR_SIZE   = 40
    HEADERS_END     = SECT_HDR_OFFSET + NUM_SECTIONS * SECT_HDR_SIZE
    FILE_ALIGN      = 0x200
    SECTION_ALIGN   = 0x1000

    headers_padded = (HEADERS_END + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)

    # One section gets one FILE_ALIGN chunk of raw data
    total_file_size = headers_padded + NUM_SECTIONS * FILE_ALIGN

    buf = bytearray(total_file_size)

    # DOS header
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 60, PE_OFFSET)

    # PE signature
    buf[PE_OFFSET:PE_OFFSET+4] = b'PE\x00\x00'

    # COFF header
    struct.pack_into('<H', buf, COFF_OFFSET,      0x014C)   # Machine: x86
    struct.pack_into('<H', buf, COFF_OFFSET + 2,   NUM_SECTIONS)
    struct.pack_into('<I', buf, COFF_OFFSET + 4,   1770997154)  # TimeDateStamp
    struct.pack_into('<H', buf, COFF_OFFSET + 16,  OPT_SIZE)
    struct.pack_into('<H', buf, COFF_OFFSET + 18,  0x0102)  # Characteristics

    # Optional header
    off = OPT_OFFSET
    struct.pack_into('<H', buf, off,         0x010B)        # PE32
    struct.pack_into('<I', buf, off + 16,    0x1000)        # Entry point
    struct.pack_into('<I', buf, off + 28,    0x00400000)    # ImageBase
    struct.pack_into('<I', buf, off + 32,    SECTION_ALIGN)
    struct.pack_into('<I', buf, off + 36,    FILE_ALIGN)
    struct.pack_into('<I', buf, off + 56,    size_of_image) # SizeOfImage
    struct.pack_into('<I', buf, off + 60,    headers_padded) # SizeOfHeaders
    struct.pack_into('<I', buf, off + 64,    0)             # Checksum
    struct.pack_into('<H', buf, off + 68,    3)             # Subsystem: CONSOLE
    struct.pack_into('<H', buf, off + 70,    0x8500)        # DllCharacteristics
    struct.pack_into('<I', buf, off + 92,    16)            # NumberOfRvaAndSizes

    # Section header: .text
    b_off = SECT_HDR_OFFSET
    buf[b_off:b_off+8] = b'.text\x00\x00\x00'
    va = SECTION_ALIGN
    raw_off = headers_padded
    struct.pack_into('<I', buf, b_off + 8,  FILE_ALIGN)    # VirtualSize
    struct.pack_into('<I', buf, b_off + 12, va)             # VirtualAddress
    struct.pack_into('<I', buf, b_off + 16, FILE_ALIGN)    # SizeOfRawData
    struct.pack_into('<I', buf, b_off + 20, raw_off)       # PointerToRawData
    struct.pack_into('<I', buf, b_off + 36, 0x60000020)    # CODE|EXECUTE|READ

    # Fill section data with padding
    buf[raw_off:raw_off + FILE_ALIGN] = b'\xCC' * FILE_ALIGN

    return bytes(buf)


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
    """Build a full TCP session: SYN, SYN-ACK, ACK, request, response(s), FIN."""
    pkts = []
    mac_c = "00:11:22:33:44:01"
    mac_s = "00:11:22:33:44:02"
    cseq = 1000
    sseq = 5000

    def pkt(src_ip, dst_ip, sp, dp, flags, seq, ack, payload=b'', src_mac=mac_c, dst_mac=mac_s):
        p = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=src_ip, dst=dst_ip) / \
            TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
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


def main():
    client_ip = "192.168.1.50"
    server_ip = "192.168.1.100"
    host      = server_ip

    # Five PEs with varying SizeOfImage
    pe_configs = [
        ("pe1.exe", 512),
        ("pe2.exe", 1024),
        ("pe3.exe", 512),
        ("pe4.exe", 4096),
        ("pe5.exe", 2048),
    ]

    all_pkts = []
    for i, (filename, img_size) in enumerate(pe_configs):
        sport = 50001 + i
        pe_data = build_pe(img_size)
        req = http_request(host, f"/{filename}")
        resp = http_response(pe_data, filename)
        pkts = build_http_stream(client_ip, server_ip, sport, 80, req, resp)
        all_pkts.extend(pkts)

    wrpcap("input.pcap", all_pkts)
    print(f"Wrote input.pcap with {len(pe_configs)} PE files")


if __name__ == "__main__":
    main()
