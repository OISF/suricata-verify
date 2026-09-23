#!/usr/bin/env python3
"""Generate input.pcap: a minimal SMTP session sending one MIME text
attachment.

The EHLO/MAIL FROM/RCPT TO/DATA commands form a single transaction.
The attachment does not contain the content matched by the filedata
firewall rule (content:"%PDF"), so the tx must complete without the rule
matching and the fail-closed default policy must drop it.

Layout (pcap_cnt):
  1-3   TCP handshake
  4     S: 220 greeting
  5     C: EHLO
  6     S: 250
  7     C: MAIL FROM
  8     S: 250
  9     C: RCPT TO
  10    S: 250
  11    C: DATA
  12    S: 354
  13    C: MIME headers + attachment part 1
  14    C: attachment part 2 + terminating dot (DATA request completes here)
  15    S: 250 queued
  16    C: QUIT
  17    S: 221
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

ETH_SRC = "00:11:22:33:44:55"
ETH_DST = "66:77:88:99:aa:bb"

SRC = "192.168.0.1"
DST = "192.168.0.2"
SPORT = 44444
DPORT = 25


def frame(pkt):
    return Ether(src=ETH_SRC, dst=ETH_DST) / pkt


BOUNDARY = "MIMEBOUNDARY03x"
FILE_CONTENT = "hello world, this is a plain text attachment\n"

MAIL = (
    "From: sender@example.com\r\n"
    "To: recipient@example.com\r\n"
    "Subject: test attachment\r\n"
    "MIME-Version: 1.0\r\n"
    f'Content-Type: multipart/mixed; boundary="{BOUNDARY}"\r\n'
    "\r\n"
    f"--{BOUNDARY}\r\n"
    'Content-Type: text/plain; name="note.txt"\r\n'
    'Content-Disposition: attachment; filename="note.txt"\r\n'
    "\r\n"
    f"{FILE_CONTENT}"
    f"--{BOUNDARY}--\r\n"
    ".\r\n"
)

# split the DATA payload in 2 so the attachment is streamed
MID = len(MAIL) // 2
DATA_PART1 = MAIL[:MID]
DATA_PART2 = MAIL[MID:]


def line(s):
    return s.encode()


def main():
    cseq = 1  # after SYN
    sseq = 1  # after SYN
    t = 0.0
    packets = []

    def c2s(payload, flags="PA", dt=0.02):
        nonlocal cseq, t
        t += dt
        p = frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags=flags, seq=cseq,
                                                ack=sseq))
        if payload:
            p = p / Raw(load=payload)
        packets.append((p, t))
        if payload:
            cseq += len(payload)

    def s2c(payload, flags="PA", dt=0.02):
        nonlocal sseq, t
        t += dt
        p = frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags=flags, seq=sseq,
                                                ack=cseq))
        if payload:
            p = p / Raw(load=payload)
        packets.append((p, t))
        if payload:
            sseq += len(payload)

    packets.append((frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=0)),
                    0.0))
    packets.append(
        (frame(IP(src=DST, dst=SRC) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=0, ack=1)),
         0.01))
    packets.append(
        (frame(IP(src=SRC, dst=DST) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq,
                                               ack=sseq)), 0.02))

    s2c(line("220 smtp.example.com ESMTP ready\r\n"))
    c2s(line("EHLO client.example.com\r\n"))
    s2c(line("250-smtp.example.com\r\n250 OK\r\n"))
    c2s(line("MAIL FROM:<sender@example.com>\r\n"))
    s2c(line("250 2.1.0 OK\r\n"))
    c2s(line("RCPT TO:<recipient@example.com>\r\n"))
    s2c(line("250 2.1.5 OK\r\n"))
    c2s(line("DATA\r\n"))
    s2c(line("354 Start mail input; end with <CRLF>.<CRLF>\r\n"))
    c2s(line(DATA_PART1))
    c2s(line(DATA_PART2))  # terminates DATA, tx request completes here
    s2c(line("250 2.0.0 OK: queued\r\n"))
    c2s(line("QUIT\r\n"))
    s2c(line("221 2.0.0 Bye\r\n"))

    for pkt, dt in packets:
        pkt.time = dt

    wrpcap("input.pcap", [pkt for pkt, _ in packets])
    print(f"wrote input.pcap with {len(packets)} packets, DATA payload {len(MAIL)} bytes")


if __name__ == "__main__":
    main()
