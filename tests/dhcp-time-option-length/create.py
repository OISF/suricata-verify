#!/usr/bin/env python3

from pathlib import Path

from scapy.layers.dhcp import BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap


TEST_DIR = Path(__file__).resolve().parent
MAGIC = bytes.fromhex("63 82 53 63")
SECONDS = bytes.fromhex("00 00 0e 10")


def dhcp_ack(option_code, option_length, packet_number):
    option_data = SECONDS
    if option_length == 5:
        option_data += b"\x00"

    options = bytes([53, 1, 5, option_code, option_length]) + option_data + bytes([255])
    packet = (
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.0.2.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            htype=1,
            hlen=6,
            xid=0x12345670 + packet_number,
            flags=0x8000,
            yiaddr="192.0.2.100",
            siaddr="192.0.2.1",
            chaddr=bytes.fromhex("02 00 00 00 00 02") + bytes(10),
            options=MAGIC,
        )
        / Raw(options)
    )
    packet.time = 1_723_370_400.0 + packet_number
    assert bytes(packet[BOOTP]).endswith(MAGIC + options)
    return packet


packets = []
for option_code in (51, 58, 59):
    for option_length in (1, 5, 4):
        packets.append(dhcp_ack(option_code, option_length, len(packets) + 1))

wrpcap(str(TEST_DIR / "input.pcap"), packets)
