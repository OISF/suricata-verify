#!/usr/bin/env python
"""
Generate input.pcap for the http-100continue-statmsg-bypass-ips test.

IPS reproducer for the 100-continue stat_msg bypass:
the http.stat_msg engine registers the same LINE response progress as
http.stat_code and shares the per-tx detect_progress bookkeeping, so
on a pre-fix build the same deviations reproduce on the
reason phrase - the final 200's reason phrase is never inspected
(FN) and the 100 line's reason phrase double-alerts (FP). The test
expects the fixed behaviour (final-200 rule fires once, 100 line
alerts once) and is red on a pre-fix build (final-200 rule 0, 100
line 2).

The pcap is the same standard A/B 100-continue exchange as the
sibling test http-100continue-statcode-bypass-ips
(byte-identical output).
"""

from scapy.all import *

SERVER = "10.0.0.2"
A_SRC = "10.0.0.1"   # flow A (baseline, normal)
B_SRC = "10.0.0.3"   # flow B (bypass, 100-continue)
A_SPORT = 10000
B_SPORT = 10001
DPORT = 80

pkts = []
t = 1700000000.0

def add(pkt, dt=0.01):
    global t
    t += dt
    pkt.time = t
    pkts.append(pkt)

def ether(src, dst, ip_src, ip_dst, sport, dport, flags, seq, ack, payload=b""):
    p = Ether(src=src, dst=dst) / IP(src=ip_src, dst=ip_dst) / \
        TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if payload:
        p = p / payload
    return p

# ---------------------------------------------------------------- flow A ---
# 10.0.0.1:10000 <-> 10.0.0.2:80   (seq 1000 / 2000)
a_seq, s_seq = 1000, 2000
add(ether("aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:02", A_SRC, SERVER, A_SPORT, DPORT, "S", a_seq, 0))
add(ether("bb:bb:bb:bb:bb:02", "aa:aa:aa:aa:aa:01", SERVER, A_SRC, DPORT, A_SPORT, "SA", s_seq, a_seq + 1))
add(ether("aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02", A_SRC, SERVER, A_SPORT, DPORT, "A", a_seq + 1, s_seq + 1))

reqA = b"GET /a HTTP/1.1\r\nHost: a.example.com\r\nUser-Agent: sv-bypass\r\n\r\n"
add(ether("aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02", A_SRC, SERVER, A_SPORT, DPORT, "PA",
         a_seq + 1, s_seq + 1, reqA))
a_ack = a_seq + 1 + len(reqA)

respA = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
add(ether("bb:bb:bb:bb:bb:02", "aa:aa:aa:aa:aa:01", SERVER, A_SRC, DPORT, A_SPORT, "PA",
         s_seq + 1, a_ack, respA))

# ---------------------------------------------------------------- flow B ---
# 10.0.0.3:10001 <-> 10.0.0.2:80   (seq 3000 / 4000)
b_seq, s2_seq = 3000, 4000
add(ether("aa:aa:aa:aa:aa:03", "bb:bb:bb:bb:bb:02", B_SRC, SERVER, B_SPORT, DPORT, "S", b_seq, 0))
add(ether("bb:bb:bb:bb:bb:02", "aa:aa:aa:aa:aa:03", SERVER, B_SRC, DPORT, B_SPORT, "SA", s2_seq, b_seq + 1))
add(ether("aa:aa:aa:aa:aa:03", "bb:bb:bb:bb:bb:02", B_SRC, SERVER, B_SPORT, DPORT, "A", b_seq + 1, s2_seq + 1))

# request with Expect: 100-continue; body (CL: 4) is never sent - the
# client waits for the 100
reqB = (b"POST /b HTTP/1.1\r\nHost: b.example.com\r\n"
        b"User-Agent: sv-bypass\r\nExpect: 100-continue\r\n"
        b"Content-Length: 4\r\n\r\n")
add(ether("aa:aa:aa:aa:aa:03", "bb:bb:bb:bb:bb:02", B_SRC, SERVER, B_SPORT, DPORT, "PA",
         b_seq + 1, s2_seq + 1, reqB))
b_ack = b_seq + 1 + len(reqB)

# server: interim 100 Continue, status line first (own packet)
resp100_line = b"HTTP/1.1 100 Continue\r\n"
add(ether("bb:bb:bb:bb:bb:02", "aa:aa:aa:aa:aa:03", SERVER, B_SRC, DPORT, B_SPORT, "PA",
         s2_seq + 1, b_ack, resp100_line))
s2_ack_line = s2_seq + 1 + len(resp100_line)

# empty line: ends the 100 headers; the parser treats the 100 as
# 100-Continue and rewinds the SAME tx backwards (progress -> LINE,
# status number left at 100)
resp100_end = b"\r\n"
add(ether("bb:bb:bb:bb:bb:02", "aa:aa:aa:aa:aa:03", SERVER, B_SRC, DPORT, B_SPORT, "PA",
         s2_ack_line, b_ack, resp100_end))
s2_ack = s2_ack_line + len(resp100_end)

# server: final 200 - on a pre-fix build the detection engine never
# inspects its stat_code (the false negative the test reproduces);
# carries the scope-control marker header + body (sids 1004/1005)
respB = (b"HTTP/1.1 200 OK\r\nX-Test: finalmarker\r\n"
        b"Content-Length: 8\r\n\r\nhello200")
add(ether("bb:bb:bb:bb:bb:02", "aa:aa:aa:aa:aa:03", SERVER, B_SRC, DPORT, B_SPORT, "PA",
         s2_ack, b_ack, respB))

wrpcap("input.pcap", pkts)
print("wrote input.pcap with %d packets" % len(pkts))
