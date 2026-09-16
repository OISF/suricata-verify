#!/usr/bin/env python3
# Generate input.pcap: one SMTP session with 18 mail envelopes over a
# single TCP connection (1 packet per line, classic pcap).
#
# test.yaml runs Suricata with app-layer.protocols.smtp.max-tx=16.
# max-tx documents the maximum number of *live* transactions per flow;
# the session's live tx count never exceeds 2, so all 18 envelopes must
# be parsed and logged. The 18th envelope becomes tx id 17 -- the rule
# for user18 (sid:2) must alert on it.
#
# With the tx_cnt high-water-mark bug in SMTPTransactionCreate() the
# 18th envelope's transaction can never be created (tx_cnt is never
# lowered when old txs are freed), the parser returns APP_LAYER_ERROR
# and the flow's app layer is disabled: only 17 envelopes get alerts
# and smtp log events.
import socket
import struct
import sys

CIP, SIP = "172.22.0.1", "172.22.0.2"
CPORT, SPORT = 58122, 25
CISN, SISP = 1000, 5000
ENVELOPES = 18
CMAC = b"\x02\x00\x00\x00\x00\x01"
SMAC = b"\x02\x00\x00\x00\x00\x02"

SYN, ACK, FIN, PSH = 0x02, 0x10, 0x01, 0x08


def csum16(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ip_hdr(src, dst, payload, ident):
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", csum16(hdr)) + hdr[12:]
    return hdr + payload


def tcp_seg(src, dst, sport, dport, seq, ack, flags, payload, ident):
    base = struct.pack(
        "!HHIIH", sport, dport, seq, ack, (5 << 12) | flags)
    tail = struct.pack("!HHH", 65535, 0, 0)  # window, csum, urgent
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(base) + len(tail) + len(payload))
    csum = csum16(pseudo + base + tail + payload)
    return ip_hdr(src, dst, base + tail[:2] + struct.pack("!H", csum) + tail[4:] + payload, ident)


class Session:
    def __init__(self):
        self.cseq, self.sseq = CISN, SISP
        self.ident = 0

    def next_ident(self):
        self.ident = (self.ident + 1) & 0xFFFF
        return self.ident

    def syn(self):
        p = tcp_seg(CIP, SIP, CPORT, SPORT, self.cseq, 0, SYN, b"", self.next_ident())
        self.cseq += 1
        return (CMAC, SMAC, p)

    def synack(self):
        p = tcp_seg(SIP, CIP, SPORT, CPORT, self.sseq, self.cseq, SYN | ACK, b"", self.next_ident())
        self.sseq += 1
        return (SMAC, CMAC, p)

    def ack(self, src, dst, sport, dport, seq, ackn):
        return (CMAC if src == CIP else SMAC, SMAC if src == CIP else CMAC,
                tcp_seg(src, dst, sport, dport, seq, ackn, ACK, b"", self.next_ident()))

    def data(self, src, dst, sport, dport, payload):
        if src == CIP:
            seq, ackn = self.cseq, self.sseq
            p = tcp_seg(src, dst, sport, dport, seq, ackn, PSH | ACK, payload, self.next_ident())
            self.cseq += len(payload)
        else:
            seq, ackn = self.sseq, self.cseq
            p = tcp_seg(src, dst, sport, dport, seq, ackn, PSH | ACK, payload, self.next_ident())
            self.sseq += len(payload)
        return (CMAC if src == CIP else SMAC, SMAC if src == CIP else CMAC, p)

    def fin(self, src, dst, sport, dport, seq, ackn):
        p = tcp_seg(src, dst, sport, dport, seq, ackn, FIN | ACK, b"", self.next_ident())
        return (CMAC if src == CIP else SMAC, SMAC if src == CIP else CMAC, p)


def main():
    s = Session()
    frames = []

    def add(src, dst, sport, dport, payload):
        frames.append(s.data(src, dst, sport, dport, payload))

    frames.append(s.syn())
    frames.append(s.synack())
    frames.append(s.ack(CIP, SIP, CPORT, SPORT, s.cseq, s.sseq))

    # welcome banner and greeting
    add(SIP, CIP, SPORT, CPORT, b"220 mail.example.com ESMTP Postfix\r\n")
    add(CIP, SIP, CPORT, SPORT, b"HELO client.example.com\r\n")
    add(SIP, CIP, SPORT, CPORT, b"250 mail.example.com\r\n")

    # 18 mail envelopes back to back
    for n in range(1, ENVELOPES + 1):
        add(CIP, SIP, CPORT, SPORT,
            b"MAIL FROM:<user%d@example.com>\r\n" % n)
        add(SIP, CIP, SPORT, CPORT, b"250 2.1.0 Ok\r\n")
        add(CIP, SIP, CPORT, SPORT,
            b"RCPT TO:<rcpt%d@example.net>\r\n" % n)
        add(SIP, CIP, SPORT, CPORT, b"250 2.1.5 Ok\r\n")
        add(CIP, SIP, CPORT, SPORT, b"DATA\r\n")
        add(SIP, CIP, SPORT, CPORT, b"354 End data with <CR><LF>.<CR><LF>\r\n")
        add(CIP, SIP, CPORT, SPORT,
            ("From: user%d@example.com\r\n"
             "Subject: envelope %d\r\n"
             "\r\n"
             "Body of envelope %d.\r\n"
             ".\r\n" % (n, n, n)).encode())
        add(SIP, CIP, SPORT, CPORT,
            b"250 2.0.0 Ok: queued as E%08X\r\n" % (0xB912F4BA + n))

    add(CIP, SIP, CPORT, SPORT, b"QUIT\r\n")
    add(SIP, CIP, SPORT, CPORT, b"221 2.0.0 Bye\r\n")

    # teardown: FIN from client, ack; FIN from server, ack
    frames.append(s.fin(CIP, SIP, CPORT, SPORT, s.cseq, s.sseq))
    s.cseq += 1
    frames.append(s.ack(SIP, CIP, SPORT, CPORT, s.sseq, s.cseq))
    frames.append(s.fin(SIP, CIP, SPORT, CPORT, s.sseq, s.cseq))
    s.sseq += 1
    frames.append(s.ack(CIP, SIP, CPORT, SPORT, s.cseq, s.sseq))

    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    with open(out, "wb") as f:
        # classic pcap, nanosecond-resolution magic (repo convention)
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t = 1700000000.0
        for sm, dm, raw in frames:
            frame = sm + dm + b"\x08\x00" + raw
            ns = int(round((t - int(t)) * 1e9))
            f.write(struct.pack("<IIII", int(t), ns, len(frame), len(frame)))
            f.write(frame)
            t += 0.05
    print("wrote %s: %d packets" % (out, len(frames)))


if __name__ == "__main__":
    main()
