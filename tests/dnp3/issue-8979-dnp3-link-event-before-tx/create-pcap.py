#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap

OUT = "input.pcap"
SERVER_PORT = 20000

# Each flow starts with a DNP3 frame whose link-header CRC is invalid, before a
# transaction exists. Valid application data then follows in the opposite
# direction to expose duplicate or misdirected event inspection.
VALID_REQUEST = bytes.fromhex("05640844010002004d6cc0c0016da0")
VALID_RESPONSE = bytes.fromhex("05640a43030004006e47c0c08100009ce8")
BAD_REQUEST = bytes.fromhex("05640844010002004c6cc0c0016da0")
BAD_RESPONSE = bytes.fromhex("05640a43030004006f47c0c08100009ce8")


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
        # Bad response CRC followed by a valid request.
        ("10.0.0.1", "10.0.0.2", 10001,
         [("toclient", BAD_RESPONSE),
          ("toserver", VALID_REQUEST)]),

        # Bad request CRC followed by a valid response.
        ("10.0.1.1", "10.0.1.2", 10002,
         [("toserver", BAD_REQUEST),
          ("toclient", VALID_RESPONSE)]),
    ]

    packets = []
    for index, (client, server, sport, segments) in enumerate(flows):
        packets.extend(make_flow(client, server, sport, segments, 1 + index * 100))
    wrpcap(OUT, packets)


if __name__ == "__main__":
    main()
