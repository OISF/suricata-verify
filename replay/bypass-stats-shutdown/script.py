from scapy.all import *

pkts = []
sport, dport = 12345, 443

pkts.append(Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=sport, dport=dport, flags='S', seq=1000))
pkts.append(Ether()/IP(src='10.0.0.2', dst='10.0.0.1')/TCP(sport=dport, dport=sport, flags='SA', seq=5000, ack=1001))
pkts.append(Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=sport, dport=dport, flags='A', seq=1001, ack=5001))

for i in range(97):
    pkts.append(Ether()/IP(src='10.0.0.1', dst='10.0.0.2')/TCP(sport=sport, dport=dport, flags='PA', seq=1001+i*100, ack=5001)/Raw(load=b'\x17\x03\x03' + b'\x00' * 100))

wrpcap('input.pcap', pkts)
