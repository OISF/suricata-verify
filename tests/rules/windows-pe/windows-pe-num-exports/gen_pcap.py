#!/usr/bin/env python3
"""Generate a PCAP with three PE files served over HTTP:
  1. many_exports.dll  — 5 exported functions
  2. few_exports.dll   — 1 exported function
  3. no_exports.exe    — no export directory
"""

import struct, io
from scapy.all import IP, TCP, Raw, Ether, wrpcap


def build_pe_with_exports(dll_name: str, export_func_names: list) -> bytes:
    """Return bytes of a minimal PE32 with an export directory."""

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

    edata_raw_off = text_raw_off + text_raw_size
    edata_va      = 2 * SECTION_ALIGN

    num_funcs = len(export_func_names)

    eat_off = 40
    npt_off = eat_off + num_funcs * 4
    ot_off  = npt_off + num_funcs * 4
    strings_off = ot_off + num_funcs * 2

    name_area = io.BytesIO()
    dll_name_rel = strings_off + name_area.tell()
    name_area.write(dll_name.encode('ascii') + b'\x00')

    func_name_rels = []
    for fn in export_func_names:
        func_name_rels.append(strings_off + name_area.tell())
        name_area.write(fn.encode('ascii') + b'\x00')

    edata_size = strings_off + name_area.tell()
    edata_raw_size = (edata_size + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)

    edata = bytearray(edata_raw_size)

    struct.pack_into('<I', edata, 12, edata_va + dll_name_rel)
    struct.pack_into('<I', edata, 16, 1)
    struct.pack_into('<I', edata, 20, num_funcs)
    struct.pack_into('<I', edata, 24, num_funcs)
    struct.pack_into('<I', edata, 28, edata_va + eat_off)
    struct.pack_into('<I', edata, 32, edata_va + npt_off)
    struct.pack_into('<I', edata, 36, edata_va + ot_off)

    for i in range(num_funcs):
        struct.pack_into('<I', edata, eat_off + i * 4, text_va + i * 4)

    for i, rel in enumerate(func_name_rels):
        struct.pack_into('<I', edata, npt_off + i * 4, edata_va + rel)

    for i in range(num_funcs):
        struct.pack_into('<H', edata, ot_off + i * 2, i)

    string_bytes = dll_name.encode('ascii') + b'\x00'
    for fn in export_func_names:
        string_bytes += fn.encode('ascii') + b'\x00'
    edata[strings_off:strings_off + len(string_bytes)] = string_bytes

    total_file_size = edata_raw_off + edata_raw_size
    size_of_image   = edata_va + SECTION_ALIGN

    buf = bytearray(total_file_size)

    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 60, PE_OFFSET)
    buf[PE_OFFSET:PE_OFFSET+4] = b'PE\x00\x00'

    struct.pack_into('<H', buf, COFF_OFFSET,      0x014C)
    struct.pack_into('<H', buf, COFF_OFFSET + 2,   NUM_SECTIONS)
    struct.pack_into('<H', buf, COFF_OFFSET + 16,  OPT_SIZE)
    struct.pack_into('<H', buf, COFF_OFFSET + 18,  0x2102)

    off = OPT_OFFSET
    struct.pack_into('<H', buf, off,         0x010B)
    struct.pack_into('<I', buf, off + 16,    0x1000)
    struct.pack_into('<I', buf, off + 28,    0x10000000)
    struct.pack_into('<I', buf, off + 32,    SECTION_ALIGN)
    struct.pack_into('<I', buf, off + 36,    FILE_ALIGN)
    struct.pack_into('<I', buf, off + 56,    size_of_image)
    struct.pack_into('<I', buf, off + 60,    headers_padded)
    struct.pack_into('<H', buf, off + 68,    3)
    struct.pack_into('<I', buf, off + 92,    16)

    struct.pack_into('<I', buf, off + 96,     edata_va)
    struct.pack_into('<I', buf, off + 96 + 4, edata_size)

    def write_section(idx, name, va, vsize, raw_off, raw_size, chars):
        b = SECT_HDR_OFFSET + idx * SECT_HDR_SIZE
        buf[b:b+8] = name.encode().ljust(8, b'\x00')[:8]
        struct.pack_into('<I', buf, b + 8,  vsize)
        struct.pack_into('<I', buf, b + 12, va)
        struct.pack_into('<I', buf, b + 16, raw_size)
        struct.pack_into('<I', buf, b + 20, raw_off)
        struct.pack_into('<I', buf, b + 36, chars)

    write_section(0, '.text',  text_va,  text_raw_size,  text_raw_off,  text_raw_size,  0x60000020)
    write_section(1, '.edata', edata_va, edata_size,     edata_raw_off, edata_raw_size, 0x40000040)

    buf[text_raw_off:text_raw_off + text_raw_size] = b'\xCC' * text_raw_size
    buf[edata_raw_off:edata_raw_off + edata_raw_size] = edata

    return bytes(buf)


def build_pe_no_exports() -> bytes:
    """Return bytes of a minimal PE32 with no export directory."""

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

    text_raw_off  = headers_padded
    text_raw_size = FILE_ALIGN
    text_va       = SECTION_ALIGN

    total_file_size = text_raw_off + text_raw_size
    size_of_image   = text_va + SECTION_ALIGN

    buf = bytearray(total_file_size)

    buf[0:2] = b'MZ'
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
    struct.pack_into('<I', buf, off + 92,    16)

    b = SECT_HDR_OFFSET
    buf[b:b+8] = b'.text\x00\x00\x00'
    struct.pack_into('<I', buf, b + 8,  text_raw_size)
    struct.pack_into('<I', buf, b + 12, text_va)
    struct.pack_into('<I', buf, b + 16, text_raw_size)
    struct.pack_into('<I', buf, b + 20, text_raw_off)
    struct.pack_into('<I', buf, b + 36, 0x60000020)

    buf[text_raw_off:text_raw_off + text_raw_size] = b'\xCC' * text_raw_size

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
    """Build a full TCP session."""
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

    # PE #1 — DLL with 5 exported functions
    many_pe = build_pe_with_exports('many.dll', [
        'Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon',
    ])

    # PE #2 — DLL with 1 exported function
    few_pe = build_pe_with_exports('few.dll', ['OnlyFunc'])

    # PE #3 — EXE with no exports
    none_pe = build_pe_no_exports()

    pkts = []

    req1 = http_request(server, '/many_exports.dll')
    resp1 = http_response(many_pe, 'many_exports.dll')
    pkts += build_http_stream(client, server, 50001, 80, req1, resp1)

    req2 = http_request(server, '/few_exports.dll')
    resp2 = http_response(few_pe, 'few_exports.dll')
    pkts += build_http_stream(client, server, 50002, 80, req2, resp2)

    req3 = http_request(server, '/no_exports.exe')
    resp3 = http_response(none_pe, 'no_exports.exe')
    pkts += build_http_stream(client, server, 50003, 80, req3, resp3)

    wrpcap('input.pcap', pkts)
    print(f'Wrote input.pcap  ({len(pkts)} packets, '
          f'PE1={len(many_pe)}B  PE2={len(few_pe)}B  PE3={len(none_pe)}B)')


if __name__ == '__main__':
    main()
