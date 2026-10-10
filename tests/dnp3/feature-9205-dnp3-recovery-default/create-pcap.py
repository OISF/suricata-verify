#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap

OUT = "input.pcap"
SERVER_PORT = 20000

# DNP3 frames from the Redmine #8980 reproducer. BAD_REQUEST has an invalid
# link-header CRC. GARBAGE contains no 0x05 0x64 start sequence.
VALID_REQUEST = bytes.fromhex("05640844010002004d6cc0c0016da0")
VALID_RESPONSE = bytes.fromhex("05640a43030004006e47c0c08100009ce8")
BAD_REQUEST = bytes.fromhex("05640844010002004c6cc0c0016da0")
GARBAGE = bytes.fromhex("deadbeef0011")


def make_flow(client, server, sport, segments, start_time):
    client_mac = "00:00:00:00:00:01"
    server_mac = "00:00:00:00:00:02"
    c2s = Ether(src=client_mac, dst=server_mac)
    s2c = Ether(src=server_mac, dst=client_mac)
    cseq = 1000
    sseq = 2000
    packets = [
        c2s / IP(src=client, dst=server) /
        TCP(sport=sport, dport=SERVER_PORT, seq=cseq, flags="S"),
        s2c / IP(src=server, dst=client) /
        TCP(sport=SERVER_PORT, dport=sport, seq=sseq, ack=cseq + 1, flags="SA"),
        c2s / IP(src=client, dst=server) /
        TCP(sport=sport, dport=SERVER_PORT, seq=cseq + 1, ack=sseq + 1, flags="A"),
    ]
    cseq += 1
    sseq += 1

    for direction, payload in segments:
        if direction == "toserver":
            packets.append(
                c2s / IP(src=client, dst=server) /
                TCP(sport=sport, dport=SERVER_PORT, seq=cseq, ack=sseq, flags="PA") /
                Raw(payload)
            )
            cseq += len(payload)
            packets.append(
                s2c / IP(src=server, dst=client) /
                TCP(sport=SERVER_PORT, dport=sport, seq=sseq, ack=cseq, flags="A")
            )
        else:
            packets.append(
                s2c / IP(src=server, dst=client) /
                TCP(sport=SERVER_PORT, dport=sport, seq=sseq, ack=cseq, flags="PA") /
                Raw(payload)
            )
            sseq += len(payload)
            packets.append(
                c2s / IP(src=client, dst=server) /
                TCP(sport=sport, dport=SERVER_PORT, seq=cseq, ack=sseq, flags="A")
            )

    packets.append(
        c2s / IP(src=client, dst=server) /
        TCP(sport=sport, dport=SERVER_PORT, seq=cseq, ack=sseq, flags="FA")
    )
    cseq += 1
    packets.append(
        s2c / IP(src=server, dst=client) /
        TCP(sport=SERVER_PORT, dport=sport, seq=sseq, ack=cseq, flags="FA")
    )
    sseq += 1
    packets.append(
        c2s / IP(src=client, dst=server) /
        TCP(sport=sport, dport=SERVER_PORT, seq=cseq, ack=sseq, flags="A")
    )

    for offset, packet in enumerate(packets):
        packet.time = start_time + offset
    return packets


def main():
    flows = [
        # Baseline: no link-layer error.
        ("10.0.0.1", "10.0.0.2", 10001,
         [("toserver", VALID_REQUEST),
          ("toclient", VALID_RESPONSE)]),

        # Valid exchange, then octets without a start sequence followed by a
        # valid request in the same TCP segment.
        ("10.0.1.1", "10.0.1.2", 10002,
         [("toserver", VALID_REQUEST),
          ("toclient", VALID_RESPONSE),
          ("toserver", GARBAGE + VALID_REQUEST),
          ("toclient", VALID_RESPONSE)]),

        # Valid exchange, then a request with a bad link-header CRC followed by
        # a valid request in the same TCP segment.
        ("10.0.2.1", "10.0.2.2", 10003,
         [("toserver", VALID_REQUEST),
          ("toclient", VALID_RESPONSE),
          ("toserver", BAD_REQUEST + VALID_REQUEST),
          ("toclient", VALID_RESPONSE)]),

        # Octets without a start sequence at the start of the flow, followed by
        # a valid request in the same TCP segment.
        ("10.0.3.1", "10.0.3.2", 10004,
         [("toserver", GARBAGE + VALID_REQUEST),
          ("toclient", VALID_RESPONSE)]),
    ]

    packets = []
    for index, (client, server, sport, segments) in enumerate(flows):
        packets.extend(make_flow(client, server, sport, segments, 1 + index * 100))
    wrpcap(OUT, packets)


if __name__ == "__main__":
    main()
