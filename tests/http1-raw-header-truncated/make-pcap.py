"""Craft two flows whose HTTP header block ends with FIN instead of a blank line.

Flow A: client sends request headers, no terminator, then FIN.
Flow B: client sends a complete request; server answers with response headers, no
terminator, then FIN.

Both check that http.header.raw still gets inspected when a block is ended by stream
closure: htp marks the state as soon as the block starts, so completion never arrives
through a hook and the buffer would otherwise stay withheld.

Checksums are not computed; Suricata needs -k none.
"""

import struct

pkts = []  # (client, flags, sport, dport, seq, ack, payload)
SEQ = {}


def emit(client, flags, ports, payload=b""):
    key = ports
    cseq, sseq = SEQ.get(key, (0, 0))
    seq = cseq if client else sseq
    ack = sseq if client else cseq
    pkts.append((client, flags, ports[0], ports[1], seq, ack, payload))
    # SYN and FIN each consume one sequence number
    extra = 1 if flags & (0x02 | 0x01) else 0
    if client:
        SEQ[key] = (cseq + len(payload) + extra, sseq)
    else:
        SEQ[key] = (cseq, sseq + len(payload) + extra)


def handshake(ports):
    emit(True, 0x02, ports)
    emit(False, 0x12, ports)
    emit(True, 0x10, ports)


# flow A: request headers cut short by the client's FIN
A = (58919, 80)
handshake(A)
req_partial = (
    b"GET /cut HTTP/1.1\r\n"
    b"Host: partial.example\r\n"
    b"User-Agent: TruncatedProbe\r\n"
)
emit(True, 0x18, A, req_partial)
emit(True, 0x01, A)  # FIN

# flow B: response headers cut short by the server's FIN
B = (58921, 80)
handshake(B)
emit(True, 0x18, B, b"GET /resp HTTP/1.1\r\nHost: whole.example\r\n\r\n")
emit(False, 0x10, B)
resp_partial = b"HTTP/1.1 200 OK\r\nServer: TruncatedServer\r\nContent-Type: text/html\r\n"
emit(False, 0x18, B, resp_partial)
emit(False, 0x01, B)  # FIN


def build(client, flags, sport, dport, seq, ack, payload):
    mac_src = b"\x00\x11\x22\x33\x44\x55" if client else b"\x00\x11\x22\x33\x44\x66"
    mac_dst = b"\x00\x11\x22\x33\x44\x66" if client else b"\x00\x11\x22\x33\x44\x55"
    ip_src = b"\xc0\xa8\x01\x0a" if client else b"\xc0\xa8\x01\x14"
    ip_dst = b"\xc0\xa8\x01\x14" if client else b"\xc0\xa8\x01\x0a"
    if not client:
        sport, dport = dport, sport
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 1, 0x4000, 64, 6, 0, ip_src, ip_dst
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


with open("input.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, p in enumerate(pkts):
        d = build(*p)
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(d), len(d)))
        f.write(d)
print("input.pcap packets:", len(pkts))
