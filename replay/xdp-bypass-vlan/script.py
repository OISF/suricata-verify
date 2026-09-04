from scapy.all import *

pkts = []

sip = "10.0.0.1"
dip = "10.1.0.1"
sport = 12345
dport = 443

pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags='S', seq=1000))
pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=dip, dst=sip)/TCP(sport=dport, dport=sport, flags='SA', seq=2000, ack=1001))
pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags='A', seq=1001, ack=2001))

for i in range(47):
    client_seq = 1001 + i * 100
    server_ack = client_seq + 100
    pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags='PA', seq=client_seq, ack=2001)/Raw(load=b'\x00' * 100))
    pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=dip, dst=sip)/TCP(sport=dport, dport=sport, flags='A', seq=2001, ack=server_ack))

pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags='FA', seq=5701, ack=2001))
pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=dip, dst=sip)/TCP(sport=dport, dport=sport, flags='FA', seq=2001, ack=5702))
pkts.append(Ether()/Dot1Q(vlan=20)/IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags='A', seq=5702, ack=2002))

wrpcap('input.pcap', pkts)
