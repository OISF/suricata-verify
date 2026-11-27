from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

pkts = []
sport, dport = 12345, 443

# TCP flow: the SYN triggers the bypass, the 99 packets after it are bypassed
pkts.append(Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=sport, dport=dport, flags='S', seq=1000))
pkts.append(Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")/IP(src='10.0.0.2', dst='10.0.0.1')/TCP(sport=dport, dport=sport, flags='SA', seq=5000, ack=1001))
pkts.append(Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=sport, dport=dport, flags='A', seq=1001, ack=5001))

for i in range(97):
    pkts.append(Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=sport, dport=dport, flags='PA', seq=1001+i*100, ack=5001)/Raw(load=b'\x17\x03\x03' + b'\x00' * 100))

# UDP flow of a single packet: bypassed, but no packet is ever bypassed
pkts.append(Ether(src="00:00:5e:00:53:01", dst="00:00:5e:00:53:02")/IP(src='10.0.0.3', dst='10.0.0.4')/UDP(sport=40000, dport=9999)/Raw(load=b'\x00' * 8))

# Replayed with the pcap timing: the pause after the SYN leaves time to set up
# the bypass before the next packet.
t0 = 1750000000
pkts[0].time = t0
for i, p in enumerate(pkts[1:]):
    p.time = t0 + 0.5 + i * 0.01

wrpcap('input.pcap', pkts)
