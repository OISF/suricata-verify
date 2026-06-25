from scapy.all import *

pkts = []

for i in range(100):
    sip = f"10.0.{i // 256}.{i % 256}"
    dip = f"10.1.{i // 256}.{i % 256}"
    sport = 10000 + i

    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=443, flags='S', seq=1000))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=443, dport=sport, flags='SA', seq=2000, ack=1001))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=443, flags='A', seq=1001, ack=2001))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=443, flags='PA', seq=1001, ack=2001)/Raw(load=b'\x00' * 100))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=443, dport=sport, flags='A', seq=2001, ack=1101))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=443, flags='PA', seq=1101, ack=2001)/Raw(load=b'\x00' * 100))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=443, dport=sport, flags='A', seq=2001, ack=1201))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=443, flags='FA', seq=1201, ack=2001))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=443, dport=sport, flags='FA', seq=2001, ack=1202))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=443, flags='A', seq=1202, ack=2002))

for i in range(100):
    sip = f"10.2.{i // 256}.{i % 256}"
    dip = f"10.3.{i // 256}.{i % 256}"
    sport = 20000 + i

    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=400, flags='S', seq=1000))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=400, dport=sport, flags='SA', seq=2000, ack=1001))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=400, flags='A', seq=1001, ack=2001))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=400, flags='PA', seq=1001, ack=2001)/Raw(load=b'\x00' * 100))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=400, dport=sport, flags='A', seq=2001, ack=1101))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=400, flags='PA', seq=1101, ack=2001)/Raw(load=b'\x00' * 100))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=400, dport=sport, flags='A', seq=2001, ack=1201))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=400, flags='FA', seq=1201, ack=2001))
    pkts.append(Ether()/IP(src=dip, dst=sip)/TCP(sport=400, dport=sport, flags='FA', seq=2001, ack=1202))
    pkts.append(Ether()/IP(src=sip, dst=dip)/TCP(sport=sport, dport=400, flags='A', seq=1202, ack=2002))

wrpcap('input.pcap', pkts)
