"""Craft a chunked request whose trailer section repeats one name 70 times.

The header repetition cap (64) must bound the merged value the same way it bounds header
values, so occurrences 2..66 are merged and 67..70 are dropped. The raw buffer keeps all of
them, which is what sid 4 asserts.

usage: python3 make-pcap.py [out.pcap]
"""
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
SYN, SYNACK, ACK, PSHACK, FIN = 0x02, 0x12, 0x10, 0x18, 0x11
CADDR, SADDR = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CMAC, SMAC = b"\x00\x11\x22\x33\x44\x55", b"\x00\x11\x22\x33\x44\x66"

nxt = {True: 1, False: 1}


def pkt(client, payload, flags):
    src, dst = (CADDR, SADDR) if client else (SADDR, CADDR)
    sport, dport = (12345, 80) if client else (80, 12345)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0x4000, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, nxt[client], nxt[not client], 5 << 4, flags,
                      65535, 0, 0)
    nxt[client] += len(payload) + (1 if flags & (0x02 | 0x01) else 0)  # SYN or FIN bit
    mac_dst, mac_src = (SMAC, CMAC) if client else (CMAC, SMAC)
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


data = b"p=0123456789" * 10
req = (
    b"POST /upload HTTP/1.1\r\nHost: a.example\r\nUser-Agent: Mozilla\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n" + b"%x\r\n" % len(data) + data + b"\r\n0\r\n"
)
req += b"".join(b"A: v%d\r\n" % i for i in range(1, 71)) + b"\r\n"

packets = [pkt(True, b"", SYN), pkt(False, b"", SYNACK), pkt(True, b"", ACK)]
buf = req
while buf:
    packets.append(pkt(True, buf[:1300], PSHACK))
    buf = buf[1300:]
resp = b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Length: 0\r\n\r\n"
packets.append(pkt(False, resp, PSHACK))
packets.append(pkt(True, b"", ACK))
packets.append(pkt(False, b"", FIN))

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)))
        f.write(p)
print(OUT, "packets:", len(packets), "trailer bytes:", len(req))
