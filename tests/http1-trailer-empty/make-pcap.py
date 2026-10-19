"""Craft a chunked request and response whose trailer sections carry no fields.

Both bodies end with a zero-length chunk followed directly by the section's empty line
("0\\r\\n\\r\\n"), which is the shape that leaves only a CRLF in the raw trailer buffer.
The rules assert that no trailer buffer is produced for it, while the header and body
buffers keep working.

Checksums are not computed; Suricata needs -k none.
"""

import struct

OUT = "input.pcap"
pkts = []  # (client, flags, seq, ack, payload)
cseq = sseq = 0


def emit(client, flags, payload=b""):
    global cseq, sseq
    pkts.append((client, flags, cseq if client else sseq, sseq if client else cseq, payload))
    # SYN and FIN each consume one sequence number
    extra = 1 if flags & (0x02 | 0x01) else 0
    if client:
        cseq += len(payload) + extra
    else:
        sseq += len(payload) + extra


emit(True, 0x02)  # SYN
emit(False, 0x12)  # SYN/ACK
emit(True, 0x10)  # ACK

data = b"p=0123456789" * 20
req = (
    b"POST /upload HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n" + b"%x\r\n" % len(data) + data + b"\r\n" + b"0\r\n\r\n"
)
buf = req
while buf:
    emit(True, 0x18, buf[:1400])
    buf = buf[1400:]

resp_data = b"r=0123456789" * 20
resp = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache\r\n"
    b"Content-Type: text/plain\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n" + b"%x\r\n" % len(resp_data) + resp_data + b"\r\n" + b"0\r\n\r\n"
)
emit(False, 0x10)
buf = resp
while buf:
    emit(False, 0x18, buf[:1400])
    buf = buf[1400:]

emit(True, 0x10)  # ACK
emit(False, 0x19)  # FIN/ACK
emit(True, 0x10)


def build(client, flags, seq, ack, payload):
    sport, dport = (58919, 80) if client else (80, 58919)
    mac_src = b"\x00\x11\x22\x33\x44\x55" if client else b"\x00\x11\x22\x33\x44\x66"
    mac_dst = b"\x00\x11\x22\x33\x44\x66" if client else b"\x00\x11\x22\x33\x44\x55"
    ip_src = b"\xc0\xa8\x01\x0a" if client else b"\xc0\xa8\x01\x14"
    ip_dst = b"\xc0\xa8\x01\x14" if client else b"\xc0\xa8\x01\x0a"
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 1, 0x4000, 64, 6, 0, ip_src, ip_dst
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, (client, flags, seq, ack, payload) in enumerate(pkts):
        d = build(client, flags, seq, ack, payload)
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(d), len(d)))
        f.write(d)
print(OUT, "packets:", len(pkts))
