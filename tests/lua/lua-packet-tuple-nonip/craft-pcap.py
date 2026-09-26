#!/usr/bin/env python3
# A single ARP packet (non-IP), so packet:tuple() must report arity 1
# (only the IP version 0), per the documented non-IP contract.
from scapy.all import ARP, Ether, wrpcap

pkt = Ether() / ARP(psrc="192.168.1.10", pdst="0.0.0.0", hwsrc="aa:bb:cc:dd:ee:ff",
                    hwdst="00:00:00:00:00:03", op=1)  # who-has
wrpcap("input.pcap", [pkt])
print("wrote input.pcap (1 ARP packet)")
