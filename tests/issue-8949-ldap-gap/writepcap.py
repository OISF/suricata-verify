#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_MAC = "00:01:02:03:04:05"
SERVER_MAC = "05:04:03:02:01:00"

BIND_REQUEST_1 = bytes.fromhex(
    "301602010160110201030400a30a04084352414d2d4d4435"
)
BIND_REQUEST_2 = bytes.fromhex(
    "301602010260110201030400a30a04084352414d2d4d4435"
)
BIND_RESPONSE_1 = bytes.fromhex(
    "3030020101612b0a010e0400040087223c3130613133633762663730386361"
    "3066333939636139396539323764613838623e"
)
BIND_RESPONSE_2 = bytes.fromhex("300c02010261070a010004000400")
UNBIND_REQUEST_3 = bytes.fromhex("30050201034200")

packets = []


def add_packet(packet):
    packet.time = 1_700_000_000 + len(packets) / 1000
    packets.append(packet)


def client_packet(src, dst, sport, seq, ack, flags="A", payload=b""):
    packet = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=389, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        packet /= Raw(payload)
    return packet


def server_packet(src, dst, dport, seq, ack, flags="A", payload=b""):
    packet = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=src, dst=dst)
        / TCP(sport=389, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        packet /= Raw(payload)
    return packet


# Flow 1: a to-server gap followed by an incomplete LDAP slice. The final
# unbind request verifies that request parsing resynchronizes.
client_ip = "1.1.1.1"
server_ip = "2.2.2.2"
client_port = 5555
add_packet(client_packet(client_ip, server_ip, client_port, 1000, 0, "S"))
add_packet(server_packet(server_ip, client_ip, client_port, 5000, 1001, "SA"))
add_packet(client_packet(client_ip, server_ip, client_port, 1001, 5001))
add_packet(
    client_packet(
        client_ip, server_ip, client_port, 1001, 5001, "PA", BIND_REQUEST_1
    )
)
add_packet(
    server_packet(
        server_ip, client_ip, client_port, 5001, 1025, "PA", BIND_RESPONSE_1
    )
)
add_packet(client_packet(client_ip, server_ip, client_port, 1025, 5051))

# Bytes 1025 through 1034 are absent from the capture. The server ACK proves
# that it received them and causes Suricata to report a ten-byte stream gap.
add_packet(client_packet(client_ip, server_ip, client_port, 1035, 5051, "PA", b"\x30"))
add_packet(server_packet(server_ip, client_ip, client_port, 5051, 1036))
add_packet(
    client_packet(
        client_ip, server_ip, client_port, 1036, 5051, "PA", UNBIND_REQUEST_3
    )
)
add_packet(server_packet(server_ip, client_ip, client_port, 5051, 1043))

# Flow 2: the same condition in the to-client direction. A second bind request
# is sent before the gap so the post-gap bind response can complete it.
client_ip = "3.3.3.3"
server_ip = "4.4.4.4"
client_port = 5556
add_packet(client_packet(client_ip, server_ip, client_port, 2000, 0, "S"))
add_packet(server_packet(server_ip, client_ip, client_port, 6000, 2001, "SA"))
add_packet(client_packet(client_ip, server_ip, client_port, 2001, 6001))
add_packet(
    client_packet(
        client_ip, server_ip, client_port, 2001, 6001, "PA", BIND_REQUEST_1
    )
)
add_packet(
    server_packet(
        server_ip, client_ip, client_port, 6001, 2025, "PA", BIND_RESPONSE_1
    )
)
add_packet(client_packet(client_ip, server_ip, client_port, 2025, 6051))
add_packet(
    client_packet(
        client_ip, server_ip, client_port, 2025, 6051, "PA", BIND_REQUEST_2
    )
)
add_packet(server_packet(server_ip, client_ip, client_port, 6051, 2049))

# Bytes 6051 through 6060 are absent from the capture.
add_packet(server_packet(server_ip, client_ip, client_port, 6061, 2049, "PA", b"\x30"))
add_packet(client_packet(client_ip, server_ip, client_port, 2049, 6062))
add_packet(
    server_packet(
        server_ip, client_ip, client_port, 6062, 2049, "PA", BIND_RESPONSE_2
    )
)
add_packet(client_packet(client_ip, server_ip, client_port, 2049, 6076))

wrpcap("input.pcap", packets)
