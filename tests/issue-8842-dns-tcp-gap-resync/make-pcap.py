#!/usr/bin/env python3
"""Generate the DNS-over-TCP gap-resynchronization PCAP for issue 8842."""

import struct

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_MAC = "02:00:00:00:88:42"
SERVER_MAC = "02:00:00:00:53:42"
CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.53"
CLIENT_PORT = 48842
SERVER_PORT = 53


def dns_query(name, tx_id):
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    message = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    message += qname + struct.pack("!HH", 1, 1)
    return struct.pack("!H", len(message)) + message


def tcp_packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    from_client = src == CLIENT_IP
    packet = (
        Ether(
            src=CLIENT_MAC if from_client else SERVER_MAC,
            dst=SERVER_MAC if from_client else CLIENT_MAC,
        )
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=65535)
    )
    if payload:
        packet /= Raw(payload)
    return packet


def main():
    client_seq = 1000
    server_seq = 9000
    baseline = dns_query("www.test.com", 0x1234)
    post_gap = dns_query("evil.test.com", 0x5678)

    # This complete record establishes DNS before the reassembly gap.
    packets = [tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, 0, "S")]
    client_seq += 1
    packets.append(
        tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, "SA")
    )
    server_seq += 1
    packets.append(
        tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, server_seq, "A")
    )
    packets.append(
        tcp_packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            "PA",
            baseline,
        )
    )
    client_seq += len(baseline)
    packets.append(
        tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, "A")
    )

    # Omit ten bytes, then supply a complete length-prefixed record whose
    # impossible DNS counts make both the resync probe and parser reject it.
    gap_size = 10
    client_seq += gap_size
    invalid = b"\x00\x0e" + b"\xff" * 14
    packets.append(
        tcp_packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            "PA",
            invalid,
        )
    )
    client_seq += len(invalid)
    packets.append(
        tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, "A")
    )

    # A fixed parser retains gap-resync state while ignoring the invalid slice,
    # then resumes inspection when this valid record begins at a segment edge.
    packets.append(
        tcp_packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            "PA",
            post_gap,
        )
    )
    client_seq += len(post_gap)
    packets.append(
        tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, "A")
    )

    packets.append(
        tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, server_seq, "FA")
    )
    client_seq += 1
    packets.append(
        tcp_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, "FA")
    )
    server_seq += 1
    packets.append(
        tcp_packet(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, server_seq, "A")
    )

    assert len(baseline) == 32
    assert len(invalid) == 16
    assert len(post_gap) == 33

    for index, packet in enumerate(packets):
        packet.time = index / 1_000_000

    wrpcap("input.pcap", packets)
    print(f"wrote {len(packets)} packets to input.pcap")


if __name__ == "__main__":
    main()
