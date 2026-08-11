#!/usr/bin/env python3

from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


TEST_DIR = Path(__file__).resolve().parent
OPTION_SEQUENCE = bytes.fromhex("35 01 05 00 33 04 00 00 0e 10 ff")


packet = (
    Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
    / IP(src="192.0.2.1", dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(
        op=2,
        htype=1,
        hlen=6,
        xid=0x12345678,
        flags=0x8000,
        yiaddr="192.0.2.100",
        siaddr="192.0.2.1",
        chaddr=bytes.fromhex("02 00 00 00 00 02") + bytes(10),
    )
    / DHCP(
        options=[
            ("message-type", "ack"),
            "pad",
            ("lease_time", 3600),
            "end",
        ]
    )
)
packet.time = 1_723_370_400.0

dhcp_payload = bytes(packet[DHCP])
assert OPTION_SEQUENCE in dhcp_payload, dhcp_payload.hex(" ")

wrpcap(str(TEST_DIR / "input.pcap"), [packet])
