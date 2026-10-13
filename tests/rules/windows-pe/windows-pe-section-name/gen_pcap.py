#!/usr/bin/env python3
"""Generate a PCAP with two PE files served over HTTP:
  1. packed.exe   — has sections: .text, .UPX0, .UPX1, .rsrc
  2. normal.exe   — has sections: .text, .rdata, .data, .rsrc
"""

import struct, io
from scapy.all import IP, TCP, Raw, Ether, wrpcap


def build_pe_with_sections(section_names: list) -> bytes:
    """Return bytes of a minimal PE32 with the given section names."""

    PE_OFFSET       = 64
    COFF_OFFSET     = PE_OFFSET + 4
    OPT_OFFSET      = COFF_OFFSET + 20
    OPT_SIZE        = 224
    NUM_SECTIONS    = len(section_names)
    SECT_HDR_OFFSET = OPT_OFFSET + OPT_SIZE
    SECT_HDR_SIZE   = 40
    HEADERS_END     = SECT_HDR_OFFSET + NUM_SECTIONS * SECT_HDR_SIZE
    FILE_ALIGN      = 0x200
    SECTION_ALIGN   = 0x1000

    headers_padded = (HEADERS_END + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)

    # Each section gets one FILE_ALIGN chunk of raw data
    total_file_size = headers_padded + NUM_SECTIONS * FILE_ALIGN
    size_of_image   = (NUM_SECTIONS + 1) * SECTION_ALIGN

    buf = bytearray(total_file_size)

    # DOS header
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 60, PE_OFFSET)

    # PE signature
    buf[PE_OFFSET:PE_OFFSET+4] = b'PE\x00\x00'

    # COFF header
    struct.pack_into('<H', buf, COFF_OFFSET,      0x014C)   # Machine: x86
    struct.pack_into('<H', buf, COFF_OFFSET + 2,   NUM_SECTIONS)
    struct.pack_into('<H', buf, COFF_OFFSET + 16,  OPT_SIZE)
    struct.pack_into('<H', buf, COFF_OFFSET + 18,  0x0102)  # Characteristics

    # Optional header
    off = OPT_OFFSET
    struct.pack_into('<H', buf, off,         0x010B)        # PE32
    struct.pack_into('<I', buf, off + 16,    0x1000)        # Entry point
    struct.pack_into('<I', buf, off + 28,    0x00400000)    # ImageBase
    struct.pack_into('<I', buf, off + 32,    SECTION_ALIGN)
    struct.pack_into('<I', buf, off + 36,    FILE_ALIGN)
    struct.pack_into('<I', buf, off + 56,    size_of_image)
    struct.pack_into('<I', buf, off + 60,    headers_padded)
    struct.pack_into('<H', buf, off + 68,    3)             # Subsystem: CONSOLE
    struct.pack_into('<I', buf, off + 92,    16)            # NumberOfRvaAndSizes

    # Section headers
    for i, name in enumerate(section_names):
        b_off = SECT_HDR_OFFSET + i * SECT_HDR_SIZE
        buf[b_off:b_off+8] = name.encode().ljust(8, b'\x00')[:8]
        va = (i + 1) * SECTION_ALIGN
        raw_off = headers_padded + i * FILE_ALIGN
        struct.pack_into('<I', buf, b_off + 8,  FILE_ALIGN)   # VirtualSize
        struct.pack_into('<I', buf, b_off + 12, va)            # VirtualAddress
        struct.pack_into('<I', buf, b_off + 16, FILE_ALIGN)    # SizeOfRawData
        struct.pack_into('<I', buf, b_off + 20, raw_off)       # PointerToRawData
        struct.pack_into('<I', buf, b_off + 36, 0x60000020)    # CODE|EXECUTE|READ

    # Fill section data with padding
    for i in range(NUM_SECTIONS):
        raw_off = headers_padded + i * FILE_ALIGN
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
    server = '192.168.1.100'
    client = '192.168.1.50'

    # PE #1 — packed-style sections (has .UPX0)
    packed_pe = build_pe_with_sections(['.text', '.UPX0', '.UPX1', '.rsrc'])

    # PE #2 — normal sections (no .UPX0)
    normal_pe = build_pe_with_sections(['.text', '.rdata', '.data', '.rsrc'])

    pkts = []
    req1 = http_request(server, '/packed.exe')
    resp1 = http_response(packed_pe, 'packed.exe')
    pkts += build_http_stream(client, server, 50001, 80, req1, resp1)

    req2 = http_request(server, '/normal.exe')
    resp2 = http_response(normal_pe, 'normal.exe')
    pkts += build_http_stream(client, server, 50002, 80, req2, resp2)

    wrpcap('input.pcap', pkts)
    print(f'Wrote input.pcap  ({len(pkts)} packets, '
          f'PE1={len(packed_pe)}B  PE2={len(normal_pe)}B)')


if __name__ == '__main__':
    main()
