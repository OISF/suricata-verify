#!/usr/bin/env python3
# SMTP session with two messages. The second message's DATA frame starts at
# stream offset 3401, past the 2500-byte inspection window; its 22 KB body
# ("AAAA line" 2000 times) arrives one line per segment, each one ACKed.
import sys
from scapy.all import IP, TCP, Ether, Raw, PcapWriter
C, S, CP, SP_ = "10.0.0.1", "10.0.0.2", 40101, 25
seq = {"c": 1000, "s": 5000}
w = PcapWriter(sys.argv[1] if len(sys.argv) > 1 else "input.pcap", sync=False)
t = [1700000000.0]
def tcp(src, flags, payload=b""):
    c2s = src == "c"
    p = Ether() / IP(src=C if c2s else S, dst=S if c2s else C) / \
        TCP(sport=CP if c2s else SP_, dport=SP_ if c2s else CP, flags=flags, seq=seq[src], ack=seq["s" if c2s else "c"]) / \
        (Raw(payload) if payload else b"")
    seq[src] += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
    t[0] += 0.001; p.time = t[0]; w.write(p)
def srv(b): tcp("s", "PA", b); tcp("c", "A")
def cli(b): tcp("c", "PA", b); tcp("s", "A")
def message(lines, body):
    cli(b"MAIL FROM:<a@b>\r\n"); srv(b"250 ok\r\n"); cli(b"RCPT TO:<c@d>\r\n"); srv(b"250 ok\r\n")
    cli(b"DATA\r\n"); srv(b"354 go\r\n")
    cli(b"Subject: x\r\n\r\n")
    for i in range(lines):
        cli(body)
    cli(b".\r\n"); srv(b"250 queued\r\n")
tcp("c", "S"); tcp("s", "SA"); tcp("c", "A")
srv(b"220 mx ESMTP\r\n"); cli(b"EHLO a\r\n"); srv(b"250 mx\r\n")
message(300, b"zzzz line\r\n")      # 3.3 KB first message, no AAAA
message(2000, b"AAAA line\r\n")     # second message: its data frame starts past offset 2500
cli(b"QUIT\r\n"); srv(b"221 bye\r\n")
tcp("c", "FA"); tcp("s", "FA"); tcp("c", "A")
w.close()
