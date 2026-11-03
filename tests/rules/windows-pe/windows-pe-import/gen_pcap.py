#!/usr/bin/env python3
"""Generate a PCAP with two PE files served over HTTP:
  1. malware_imports.exe — imports ws2_32.dll, wininet.dll, advapi32.dll, kernel32.dll
  2. benign_imports.exe  — imports only kernel32.dll, user32.dll

Full TCP handshake so Suricata sees established flows and HTTP app-layer.
"""

import struct, io
from scapy.all import IP, TCP, Raw, Ether, wrpcap

def build_pe_with_imports(dll_names: list) -> bytes:
    """Return bytes of a minimal PE32 whose import table lists *dll_names*."""

    PE_OFFSET       = 64
    COFF_OFFSET     = PE_OFFSET + 4
    OPT_OFFSET      = COFF_OFFSET + 20
    OPT_SIZE        = 224
    NUM_SECTIONS    = 2
    SECT_HDR_OFFSET = OPT_OFFSET + OPT_SIZE
    SECT_HDR_SIZE   = 40
    HEADERS_END     = SECT_HDR_OFFSET + NUM_SECTIONS * SECT_HDR_SIZE
    FILE_ALIGN      = 0x200
    SECTION_ALIGN   = 0x1000

    headers_padded = (HEADERS_END + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)

    text_raw_off  = headers_padded
    text_raw_size = FILE_ALIGN
    text_va       = SECTION_ALIGN

    idata_raw_off  = text_raw_off + text_raw_size
    idata_va       = 2 * SECTION_ALIGN

    num_dlls = len(dll_names)
    idt_size = (num_dlls + 1) * 20

    name_area = io.BytesIO()
    name_offsets = []
    for name in dll_names:
        name_offsets.append(idt_size + name_area.tell())
        name_area.write(name.encode('ascii') + b'\x00')
    if name_area.tell() % 2:
        name_area.write(b'\x00')

    idata_content = bytearray(idt_size) + name_area.getvalue()

    for i, dll in enumerate(dll_names):
        base = i * 20
        name_rva = idata_va + name_offsets[i]
        struct.pack_into('<I', idata_content, base + 12, name_rva)

    idata_raw_size = (len(idata_content) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    idata_content += b'\x00' * (idata_raw_size - len(idata_content))

    total_file_size = idata_raw_off + idata_raw_size
    size_of_image   = idata_va + SECTION_ALIGN

    buf = bytearray(total_file_size)

    buf[0:2]   = b'MZ'
    struct.pack_into('<I', buf, 60, PE_OFFSET)

    buf[PE_OFFSET:PE_OFFSET+4] = b'PE\x00\x00'

    struct.pack_into('<H', buf, COFF_OFFSET,      0x014C)
    struct.pack_into('<H', buf, COFF_OFFSET + 2,   NUM_SECTIONS)
    struct.pack_into('<H', buf, COFF_OFFSET + 16,  OPT_SIZE)
    struct.pack_into('<H', buf, COFF_OFFSET + 18,  0x0102)

    off = OPT_OFFSET
    struct.pack_into('<H', buf, off,         0x010B)
    struct.pack_into('<I', buf, off + 16,    0x1000)
    struct.pack_into('<I', buf, off + 28,    0x00400000)
    struct.pack_into('<I', buf, off + 32,    SECTION_ALIGN)
    struct.pack_into('<I', buf, off + 36,    FILE_ALIGN)
    struct.pack_into('<I', buf, off + 56,    size_of_image)
    struct.pack_into('<I', buf, off + 60,    headers_padded)
    struct.pack_into('<H', buf, off + 68,    3)
    struct.pack_into('<H', buf, off + 70,    0x8160)
    struct.pack_into('<I', buf, off + 92,    16)

    struct.pack_into('<I', buf, off + 96 + 8,  idata_va)
    struct.pack_into('<I', buf, off + 96 + 12, idt_size)

    def write_section(idx, name, va, vsize, raw_off, raw_size, chars):
        b = SECT_HDR_OFFSET + idx * SECT_HDR_SIZE
        buf[b:b+8] = name.encode().ljust(8, b'\x00')[:8]
        struct.pack_into('<I', buf, b + 8,  vsize)
        struct.pack_into('<I', buf, b + 12, va)
        struct.pack_into('<I', buf, b + 16, raw_size)
        struct.pack_into('<I', buf, b + 20, raw_off)
        struct.pack_into('<I', buf, b + 36, chars)

    write_section(0, '.text',  text_va,  text_raw_size,  text_raw_off,  text_raw_size,  0x60000020)
    write_section(1, '.idata', idata_va, len(idata_content), idata_raw_off, idata_raw_size, 0xC0000040)

    buf[text_raw_off:text_raw_off + text_raw_size] = b'\xCC' * text_raw_size
    buf[idata_raw_off:idata_raw_off + len(idata_content)] = idata_content

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

    # 3-way handshake
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'S', cseq, 0))
    cseq += 1
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'SA', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))
    sseq += 1
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'A', cseq, sseq))

    # HTTP request
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'PA', cseq, sseq, request))
    cseq += len(request)
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'A', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))

    # HTTP response (possibly multiple segments)
    seg_size = 1400
    off = 0
    while off < len(response):
        chunk = response[off:off+seg_size]
        pkts.append(pkt(server_ip, client_ip, dport, sport, 'PA', sseq, cseq, chunk, src_mac=mac_s, dst_mac=mac_c))
        sseq += len(chunk)
        pkts.append(pkt(client_ip, server_ip, sport, dport, 'A', cseq, sseq))
        off += seg_size

    # FIN from server
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'FA', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))
    sseq += 1
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'A', cseq, sseq))

    # FIN from client
    pkts.append(pkt(client_ip, server_ip, sport, dport, 'FA', cseq, sseq))
    cseq += 1
    pkts.append(pkt(server_ip, client_ip, dport, sport, 'A', sseq, cseq, src_mac=mac_s, dst_mac=mac_c))

    return pkts


def main():
    server = '192.168.1.100'
    client = '192.168.1.50'

    # PE #1 — "malware-like" imports
    mal_pe = build_pe_with_imports([
        'KERNEL32.dll',
        'WS2_32.dll',       # Winsock networking
        'WININET.dll',      # HTTP / FTP client
        'ADVAPI32.dll',     # Registry / crypto tokens
    ])
    # PE #2 — benign imports only
    benign_pe = build_pe_with_imports([
        'KERNEL32.dll',
        'USER32.dll',
    ])

    pkts = []
    # Stream 1: malware
    req1 = http_request(server, '/malware_imports.exe')
    resp1 = http_response(mal_pe, 'malware_imports.exe')
    pkts += build_http_stream(client, server, 50001, 80, req1, resp1)

    # Stream 2: benign
    req2 = http_request(server, '/benign_imports.exe')
    resp2 = http_response(benign_pe, 'benign_imports.exe')
    pkts += build_http_stream(client, server, 50002, 80, req2, resp2)

    wrpcap('input.pcap', pkts)
    print(f'Wrote input.pcap  ({len(pkts)} packets, '
          f'PE1={len(mal_pe)}B  PE2={len(benign_pe)}B)')


if __name__ == '__main__':
    main()
