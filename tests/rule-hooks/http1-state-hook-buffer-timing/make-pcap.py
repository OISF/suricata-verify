"""HTTP/1.1 request with headers, body, last chunk and trailers in separate packets.

The rule hooked at the trailer state must be decided at the header packet, so the stages
need to be separable: 1s per packet, headers at #4, trailers at #8.

usage: python3 make-pcap.py [out.pcap]
"""
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
SYN, SYNACK, ACK, PSHACK, FIN, FINACK = 0x02, 0x12, 0x10, 0x18, 0x11, 0x19
CPORT, SPORT = 12345, 80
CADDR, SADDR = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
CMAC, SMAC = b"\x00\x11\x22\x33\x44\x55", b"\x00\x11\x22\x33\x44\x66"

nxt = {True: 1, False: 1}
now = [0.0]


def pkt(client, payload, flags):
    src, dst = (CADDR, SADDR) if client else (SADDR, CADDR)
    sport, dport = (CPORT, SPORT) if client else (SPORT, CPORT)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0x4000, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, nxt[client], nxt[not client], 5 << 4, flags,
                      65535, 0, 0)
    nxt[client] += len(payload) + (1 if flags & (0x02 | 0x01) else 0)
    mac_dst, mac_src = (SMAC, CMAC) if client else (CMAC, SMAC)
    t = now[0]
    now[0] += 1.0
    return t, mac_dst + mac_src + b"\x08\x00" + ip + tcp + payload


HDR = (
    b"GET /trailer-probe HTTP/1.1\r\n"
    b"Host: www.example.com\r\n"
    b"User-Agent: curl/8\r\n"
    b"Accept: */*\r\n"
    b"TE: trailers\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
)
CHUNK1 = b"6\r\n012345\r\n"
CHUNK2 = b"6\r\n6789ab\r\n"
LAST = b"0\r\n"
# trailers arrive later than the headers: the header buffer is complete long before
TRAILERS = (
    b"Check-Sum: 0123456789ab\r\n"
    b"Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\n"
    b"\r\n"
)
RESP = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\n0123456789ab"

pkts = [
    pkt(True, b"", SYN),
    pkt(False, b"", SYNACK),
    pkt(True, b"", ACK),
    pkt(True, HDR, PSHACK),        # request headers
    pkt(True, CHUNK1, PSHACK),     # body part 1
    pkt(True, CHUNK2, PSHACK),     # body part 2
    pkt(True, LAST, PSHACK),       # last chunk
    pkt(True, TRAILERS, PSHACK),   # trailers
    pkt(False, RESP, PSHACK),      # response
    pkt(True, b"", FIN),
    pkt(False, b"", ACK),
    pkt(False, b"", FINACK),
    pkt(True, b"", ACK),
]

with open(OUT, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for t, d in pkts:
        f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(d), len(d)))
        f.write(d)
print(f"wrote {OUT}: {len(pkts)} pkts, timestamps {int(pkts[0][0])}..{int(pkts[-1][0])}")
