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




def dnp3_crc(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc & 0xFFFF).to_bytes(2, "little")


def embedded_frame():
    """A frame with a valid link header whose single 16-octet data block holds
    a complete valid request, followed by a wrong block CRC."""
    block = VALID_REQUEST + b"\x00"
    header = bytes.fromhex("0564") + bytes([5 + len(block)]) + bytes.fromhex("c4010002 00".replace(" ", ""))
    header += dnp3_crc(header)
    good = dnp3_crc(block)
    bad = bytes([good[0] ^ 0xFF, good[1]])
    return header + block + bad


def bad_crc_response():
    """A response with a valid link header whose 16-octet data block fails its
    CRC. The block holds a start sequence followed by an invalid link header."""
    block = VALID_RESPONSE[10:15] + bytes.fromhex("05640a43") + bytes(7)
    header = VALID_RESPONSE[:2] + bytes([5 + len(block)]) + VALID_RESPONSE[3:8]
    header += dnp3_crc(header)
    good = dnp3_crc(block)
    bad = bytes([good[0] ^ 0xFF, good[1]])
    return header + block + bad


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
        # A valid exchange, then a frame whose body fails its block CRC and
        # contains a complete valid request, followed by a valid request, in
        # one segment.
        ("10.0.6.1", "10.0.6.2", 10007,
         [("toserver", VALID_REQUEST),
          ("toclient", VALID_RESPONSE),
          ("toserver", embedded_frame() + VALID_REQUEST),
          ("toclient", VALID_RESPONSE)]),

        # The same in the other direction: a valid exchange, a request, then a
        # response whose block CRC fails, with a start sequence and an invalid
        # link header in its body, followed by a valid response.
        ("10.0.7.1", "10.0.7.2", 10008,
         [("toserver", VALID_REQUEST),
          ("toclient", VALID_RESPONSE),
          ("toserver", VALID_REQUEST),
          ("toclient", bad_crc_response() + VALID_RESPONSE)]),
    ]

    packets = []
    for index, (client, server, sport, segments) in enumerate(flows):
        packets.extend(make_flow(client, server, sport, segments, 1 + index * 100))
    wrpcap(OUT, packets)


if __name__ == "__main__":
    main()
