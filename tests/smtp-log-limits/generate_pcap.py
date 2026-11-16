#!/usr/bin/env python3
"""SMTP session with oversized transaction lists.

100 RCPT TO entries (cap 64), 200 URLs in the body (cap 128) and 200
attachment filenames (cap 128). The logger must mark each cut and keep
the record under the 10 MiB drop.
"""
from scapy.all import Ether, IP, TCP, Raw, wrpcap

RCPT = 100
URLS = 150
ATTACH = 150

pre = ["EHLO example.com", "MAIL FROM:<alice@example.com>"]
pre += [f"RCPT TO:<user{i}@example.org>" for i in range(RCPT)]
pre.append("DATA")
client_pre = ("\r\n".join(pre) + "\r\n").encode()

lines = [
    "From: alice@example.com",
    "To: user0@example.org",
    "Subject: limits",
    'Content-Type: multipart/mixed; boundary="B"',
    "MIME-Version: 1.0",
    "",
    "--B",
    "Content-Type: text/plain",
    "",
]
lines += [f"http://example.org/u{i}" for i in range(URLS)]
for i in range(ATTACH):
    lines += [
        "--B",
        f'Content-Disposition: attachment; filename="file{i}.bin"',
        "Content-Type: application/octet-stream",
        "",
        "x",
    ]
lines += ["--B--", ".", "QUIT", ""]
client_msg = ("\r\n".join(lines)).encode()

server_pre = b""
for _ in range(RCPT + 1):
    server_pre += b"250 OK\r\n"
server_pre += b"354 go\r\n"
server_post = b"250 queued\r\n221 bye\r\n"

e1, e2 = "02:42:00:00:00:01", "02:42:00:00:00:02"


def pkt(src, dst, sport, dport, flags, seq, ack, load=b""):
    p = EtherIOS(src, dst) / IP(src="192.0.2.1" if src == e1 else "192.0.2.2",
                                dst="192.0.2.2" if src == e1 else "192.0.2.1")
    p = p / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if load:
        p = p / Raw(load=load)
    return p


def EtherIOS(src, dst):
    return Ether(src=src, dst=dst)


cseq, sseq = 1001, 2001
pkts = [
    pkt(e1, e2, 1234, 25, "S", cseq - 1, sseq - 1),
    pkt(e2, e1, 25, 1234, "SA", sseq - 1, cseq),
    pkt(e1, e2, 1234, 25, "PA", cseq, sseq, client_pre),
]
cseq += len(client_pre)
pkts.append(pkt(e2, e1, 25, 1234, "PA", sseq, cseq, server_pre))
sseq += len(server_pre)
pkts.append(pkt(e1, e2, 1234, 25, "PA", cseq, sseq, client_msg))
cseq += len(client_msg)
pkts.append(pkt(e2, e1, 25, 1234, "PA", sseq, cseq, server_post))

wrpcap("smtp.pcap", pkts)
print("client bytes:", len(client_pre)+len(client_msg), "packets:", len(pkts))
