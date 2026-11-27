# 100 TCP sessions to port 443 (bypassed by test.rules), then, after a gap longer than
# flow-timeouts.tcp.bypassed (5s), 100 new TCP sessions to port 400 spread over 6s.
# New flows make workers walk whole hash rows (hash-size 10), so on a build without the
# fix a worker times out the bypassed flows before the flow manager can.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

def session(sip, dip, sport, dport, t, pkts):
    seq = [
        (sip, dip, sport, dport, 'S', 1000, 0, b''),
        (dip, sip, dport, sport, 'SA', 2000, 1001, b''),
        (sip, dip, sport, dport, 'A', 1001, 2001, b''),
        (sip, dip, sport, dport, 'PA', 1001, 2001, b'\x00' * 100),
        (dip, sip, dport, sport, 'A', 2001, 1101, b''),
        (sip, dip, sport, dport, 'PA', 1101, 2001, b'\x00' * 100),
        (dip, sip, dport, sport, 'A', 2001, 1201, b''),
        (sip, dip, sport, dport, 'FA', 1201, 2001, b''),
        (dip, sip, dport, sport, 'FA', 2001, 1202, b''),
        (sip, dip, sport, dport, 'A', 1202, 2002, b''),
    ]
    for k, (s, d, sp, dp, fl, sq, ack, load) in enumerate(seq):
        p = Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02") / IP(src=s, dst=d) / TCP(sport=sp, dport=dp, flags=fl, seq=sq, ack=ack)
        if load:
            p = p / Raw(load=load)
        p.time = t + k * 0.001
        pkts.append(p)

pkts = []
t0 = 1750000000.0
for i in range(100):
    session(f"10.0.0.{i}", f"10.1.0.{i}", 10000 + i, 443, t0 + i * 0.01, pkts)
for i in range(100):
    session(f"10.2.0.{i}", f"10.3.0.{i}", 20000 + i, 400, t0 + 8 + i * 0.06, pkts)
wrpcap('input.pcap', pkts)
