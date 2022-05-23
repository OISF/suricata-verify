from scapy.all import Ether, Dot1Q, IP, TCP, wrpcap

pkts = []

src_ip = f"192.168.1.1"

pkts = [
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:01:02:03:04:05")
    / Dot1Q(vlan=6)
    / IP(dst="255.255.255.255", src=src_ip, id=0)
    / TCP(sport=i, dport=i)
    for i in range(30, 50)
]
pkts += [
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:01:02:03:04:05")
    / Dot1Q(vlan=6)
    / IP(dst="255.255.255.255", src=src_ip, id=0)
    / TCP(sport=45, dport=45)
    for _ in range(10)
]
pkts += [
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:01:02:03:04:05")
    / Dot1Q(vlan=6)
    / IP(dst="255.255.255.255", src=src_ip, id=0)
    / TCP(sport=4, dport=4)
    for _ in range(10)
]

wrpcap("input.pcap", pkts)
