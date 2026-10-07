#!/usr/bin/env python3
# Writes input.pcap and the pcap-log file Suricata is expected to write.
from decimal import Decimal
import os

from scapy.all import Ether, GRE, IP, PcapWriter, Raw, UDP
from scapy.contrib.erspan import ERSPAN_II
from scapy.layers.vxlan import VXLAN

# same as the PCAP_SNAPLEN Suricata uses for pcap-log
SNAPLEN = 262144
TS = Decimal(1700000000)
OUTER_MAC = dict(src='00:00:00:00:01:01', dst='00:00:00:00:01:02')
INNER_MAC = dict(src='00:00:00:00:02:01', dst='00:00:00:00:02:02')


def inner(payload):
    # identical 5-tuple in every tunnel and outside of tunnels
    return (Ether(**INNER_MAC) / IP(src='10.1.2.4', dst='10.1.2.3') /
            UDP(sport=1234, dport=5678) / Raw(payload))


def vxlan(src, vni, payload):
    return (Ether(**OUTER_MAC) / IP(src=src, dst='192.168.1.2') /
            UDP(sport=50000, dport=4789) / VXLAN(flags=0x08, vni=vni) /
            inner(payload))


def erspan(src, session, payload):
    return (Ether(**OUTER_MAC) / IP(src=src, dst='192.168.1.2') / GRE() /
            ERSPAN_II(session_id=session) / inner(payload))


def plain(payload):
    return Ether(**OUTER_MAC) / inner(payload)[IP]


pkts = []
for rnd in (1, 2):
    # tunnel id 2 in suricata.yaml
    pkts.append(vxlan('192.168.1.3', 123, f'vxlan-known-{rnd}'))
    # tunnel id 1 in suricata.yaml
    pkts.append(erspan('192.168.1.4', 321, f'erspan-known-{rnd}'))
    # same sender as tunnel id 2 but VNI not in suricata.yaml
    pkts.append(vxlan('192.168.1.3', 999, f'vxlan-unknown-{rnd}'))
    # not tunneled
    pkts.append(plain(f'plain-{rnd}'))

for i, p in enumerate(pkts):
    p.time = TS + Decimal(i) / 1000


def write(path, idx):
    w = PcapWriter(path, linktype=1, snaplen=SNAPLEN)
    for i in idx:
        w.write(pkts[i])
    w.close()


here = os.path.dirname(os.path.abspath(__file__))
write(os.path.join(here, 'input.pcap'), range(len(pkts)))

# alert on vxlan-known-1 by tenant 2
os.makedirs(os.path.join(here, 'expected'), exist_ok=True)
write(os.path.join(here, 'expected', f'log.pcap.{int(TS)}'), [0, 4])
