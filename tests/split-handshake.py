#!/usr/bin/env python
from scapy.all import *

src='1.1.1.1'
dst='2.2.2.2'
dport=80
sport=12345
smac='11:11:11:11:11:11'
dmac='22:22:22:22:22:22'

pkts = []

# CLIENT: SYN
pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="S",seq=1000)
# SERVER: ACK
pkts += Ether(dst=smac, src=dmac)/ \
    IP(dst=src, src=dst)/TCP(dport=sport,sport=dport,flags="A",seq=2000,ack=1001)
# SERVER: SYN
pkts += Ether(dst=smac, src=dmac)/ \
    IP(dst=src, src=dst)/TCP(dport=sport,sport=dport,flags="S",seq=3000)
# CLIENT: SYN/ACK
pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="SA",seq=1000,ack=3001)
# SERVER: ACK
pkts += Ether(dst=smac, src=dmac)/ \
    IP(dst=src, src=dst)/TCP(dport=sport,sport=dport,flags="A",seq=3001,ack=1001)

# CLIENT: EVIL DATA
pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="A",seq=1001,ack=3001)/"EVIL"
# SERVER: ACK EVIL DATA
pkts += Ether(dst=smac, src=dmac)/ \
    IP(dst=src, src=dst)/TCP(dport=sport,sport=dport,flags="A",seq=3001,ack=1005)

pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="R",seq=1005)

wrpcap('split-handshake-5whs.pcap', pkts)


pkts = []

# CLIENT: SYN
pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="S",seq=1000)
# SERVER: SYN
pkts += Ether(dst=smac, src=dmac)/ \
    IP(dst=src, src=dst)/TCP(dport=sport,sport=dport,flags="S",seq=3000)
# CLIENT: SYN/ACK
pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="SA",seq=1000,ack=3001)
# SERVER: ACK
pkts += Ether(dst=smac, src=dmac)/ \
    IP(dst=src, src=dst)/TCP(dport=sport,sport=dport,flags="A",seq=3001,ack=1001)

# CLIENT: EVIL DATA
pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="A",seq=1001,ack=3001)/"EVIL"
# SERVER: ACK EVIL DATA
pkts += Ether(dst=smac, src=dmac)/ \
    IP(dst=src, src=dst)/TCP(dport=sport,sport=dport,flags="A",seq=3001,ack=1005)

pkts += Ether(dst=dmac, src=smac)/ \
    IP(dst=dst, src=src)/TCP(dport=dport,sport=sport,flags="R",seq=1005)

wrpcap('split-handshake-4whs.pcap', pkts)
