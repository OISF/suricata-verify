Decode ARP packet over GRE.

PCAP made with the following scapy script:

```
#!/usr/bin/env python
from scapy.all import *

pkts = []

pkts += Ether(dst='05:04:03:02:01:00', src='00:01:02:03:04:05')/Dot1Q(vlan=6)/IP(src='1.1.1.1', dst='2.2.2.2')/GRE()/ARP()

wrpcap('arp-encap.pcap', pkts)
```
