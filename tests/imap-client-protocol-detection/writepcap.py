#!/usr/bin/env python3

from decimal import Decimal

from scapy.all import Ether, IP, Raw, TCP, wrpcap


class Flow:
    def __init__(self, port, server_port=143, window=65535, seq=(1000, 9000)):
        self.port = port
        self.server_port = server_port
        self.window = window
        self.seq = list(seq)
        self.packets = []
        self.send(False, flags="S")
        self.send(True, flags="SA")
        self.send(False, flags="A")

    def send(self, server, payload=b"", flags="PA"):
        client = ("02:00:00:00:00:01", "192.0.2.1", self.port)
        peer = ("02:00:00:00:00:02", "192.0.2.2", self.server_port)
        src, dst = (peer, client) if server else (client, peer)
        pkt = (
            Ether(src=src[0], dst=dst[0])
            / IP(src=src[1], dst=dst[1])
            / TCP(sport=src[2], dport=dst[2], seq=self.seq[server],
                  ack=0 if flags == "S" else self.seq[not server],
                  flags=flags, window=self.window)
        )
        self.packets.append(pkt / Raw(load=payload) if payload else pkt)
        self.seq[server] += len(payload) + ("S" in flags) + ("F" in flags)


def capability_nonstandard_port():
    flow = Flow(42010, server_port=1143)
    payload = b'a001 CAPABILITY\r\n'
    flow.send(False, payload, flags='PA')
    return flow.packets


def fragmented_command_detection():
    flow = Flow(42020)
    seg1 = b'A1 LOGIN username '
    seg2 = b'password\r\n'
    flow.send(False, seg1, flags='PA')
    flow.send(True, flags='A')
    flow.send(False, seg2, flags='PA')
    flow.send(True, flags='A')
    return flow.packets

packets = []
timestamp = 1_000_000
for scenario, interval in [
    (capability_nonstandard_port, 1000000),
    (fragmented_command_detection, 1000000),
]:
    for pkt in scenario():
        pkt.time = Decimal(timestamp) / 1_000_000
        packets.append(pkt)
        timestamp += interval

wrpcap("input.pcap", packets)
