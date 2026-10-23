#!/usr/bin/env python3
"""
Generate input.pcap: a two segment TCP stream with QinQ frames of an
unrelated flow in between the segments. Control for
../bug-9125-vlan-recycle-split.

The stream carries "FOO" and "BAR" in two separate segments, so the
'content:"FOOBAR"' signature in test.rules can only match on reassembled
data. Between the two segments go PRIM_COUNT frames of a flow that is not
part of the stream at all and never gets an answer: they carry 3 802.1Q
tags, so DecodeVLAN() fills all VLAN_MAX_LAYERS vlan id slots of the
pooled packet that decodes them.

This is the same trace as ../bug-9125-vlan-recycle-split with only 2
vlan tags on the priming frames, so it exercises the vlan id slots that
the recycle path did clear. It must give one flow and one alert, also
without the fix: the differential that pins the bug is the third tag.

Run from the test directory:

    ./writepcap.py
"""

from scapy.all import Dot1Q, Ether, IP, Raw, TCP, UDP, wrpcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
CPORT, SPORT = 1234, 80
CSEQ, SSEQ = 1000, 5000

PRIM_HOSTS = (("02:00:00:00:00:03", "192.0.2.200"), ("02:00:00:00:00:04", "192.0.2.201"))

# the vlan ids of the priming frames, outer first
PRIM_VLAN_IDS = (100, 200)
PRIM_COUNT = 3


def with_vlan_tags(eth, vlan_ids, inner):
    """Encapsulate an Ethernet frame in len(vlan_ids) 802.1Q headers."""
    pkt = eth
    for i, vlan in enumerate(vlan_ids):
        # below the innermost tag sits the IPv4 header
        proto = 0x8100 if i + 1 < len(vlan_ids) else 0x0800
        pkt = pkt / Dot1Q(vlan=vlan, type=proto)
    return pkt / inner


def to_stream(sender, flags, seq, ack, payload=b""):
    """A packet of the monitored stream. The stream is not VLAN tagged."""
    if sender == CLIENT:
        dst, dmac, smac, sport, dport = SERVER, SERVER_MAC, CLIENT_MAC, CPORT, SPORT
    else:
        dst, dmac, smac, sport, dport = CLIENT, CLIENT_MAC, SERVER_MAC, SPORT, CPORT
    return Ether(dst=dmac, src=smac) / IP(src=sender, dst=dst) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / Raw(load=payload)


def priming(index):
    """A frame of a flow unrelated to the stream, triple tagged."""
    smac, src = PRIM_HOSTS[0]
    dmac, dst = PRIM_HOSTS[1]
    inner = IP(src=src, dst=dst) / UDP(sport=53535 + index, dport=53535) / Raw(load=b"PRIMING")
    return with_vlan_tags(Ether(dst=dmac, src=smac), PRIM_VLAN_IDS, inner)


def build():
    pkts = [
        to_stream(CLIENT, "S", CSEQ, 0),
        to_stream(SERVER, "SA", SSEQ, CSEQ + 1),
        to_stream(CLIENT, "A", CSEQ + 1, SSEQ + 1),
        to_stream(CLIENT, "PA", CSEQ + 1, SSEQ + 1, b"FOO"),
    ]
    pkts.extend(priming(i) for i in range(PRIM_COUNT))
    pkts += [
        to_stream(CLIENT, "PA", CSEQ + 4, SSEQ + 1, b"BAR"),
        to_stream(SERVER, "A", SSEQ + 1, CSEQ + 7),
        to_stream(CLIENT, "FA", CSEQ + 7, SSEQ + 1),
        to_stream(SERVER, "FA", SSEQ + 1, CSEQ + 8),
    ]
    return pkts


if __name__ == "__main__":
    pkts = build()
    for i, pkt in enumerate(pkts):
        # fixed stamps, so re-running the script gives a byte identical pcap
        pkt.time = 1758000000.0 + i * 0.001
    wrpcap("input.pcap", pkts)
