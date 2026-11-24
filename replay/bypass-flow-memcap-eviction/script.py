# 50 single-packet UDP flows to port 9999 (bypassed by test.rules), then, after
# a pause of 32 seconds, 750 single-packet UDP flows to port 5555 that exhaust
# the flow memcap. Forced eviction only takes flows that look idle for 30
# seconds or more, which by then only holds for the bypassed flows.
from scapy.all import Ether, IP, UDP, Raw, wrpcap

pkts = []
t0 = 1750000000.0

def udp(src, sport, dport, t):
    p = Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")/IP(src=src, dst="10.1.0.1")/UDP(sport=sport, dport=dport)/Raw(load=b'\x00' * 8)
    p.time = t
    pkts.append(p)

for i in range(50):
    udp("10.0.0.%d" % (i + 1), 40000 + i, 9999, t0 + i * 0.001)
for i in range(750):
    udp("10.2.%d.%d" % (i // 250, i % 250 + 1), 20000 + i, 5555, t0 + 32 + i * 0.0005)

wrpcap('input.pcap', pkts)
