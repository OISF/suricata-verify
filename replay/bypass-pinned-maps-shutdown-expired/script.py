# 40 single-packet UDP flows (bypassed by test.rules), then, 13 seconds later,
# 10 more. With flow-timeouts.udp.bypassed at 10 seconds and Suricata stopped
# 1 second after the replay, the first 40 flows have timed out at the stop and
# the last 10 have not. No packet is bypassed, so no flow is refreshed.
from scapy.all import Ether, IP, UDP, Raw, wrpcap

pkts = []
t0 = 1750000000.0

def udp(src, sport, t):
    p = Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")/IP(src=src, dst="10.1.0.1")/UDP(sport=sport, dport=9999)/Raw(load=b'\x00' * 8)
    p.time = t
    pkts.append(p)

for i in range(40):
    udp("10.0.0.%d" % (i + 1), 40000 + i, t0 + i * 0.001)
for i in range(10):
    udp("10.2.0.%d" % (i + 1), 20000 + i, t0 + 13 + i * 0.001)

wrpcap('input.pcap', pkts)
