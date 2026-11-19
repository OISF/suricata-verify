from scapy.all import *
from scapy.contrib.erspan import ERSPAN_II

pkts = []

sip = "10.0.0.1"
dip = "10.1.0.1"

for i in range(100):
    pkts.append(Ether()/IP(dst='192.168.1.2', src='192.168.1.3')/GRE()/ERSPAN_II(session_id=321)/Ether()/IP(src=sip, dst=dip)/UDP()/"pxng")

wrpcap('input.pcap', pkts)
