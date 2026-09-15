#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_IP = "192.0.2.11"
SERVER_IP = "192.0.2.12"
CLIENT_MAC = "02:00:00:00:00:11"
SERVER_MAC = "02:00:00:00:00:12"
CLIENT_PORT = 40143
SERVER_PORT = 143


def cpacket(seq, ack, flags, payload=b""):
    p = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
        sport=CLIENT_PORT, dport=SERVER_PORT, seq=seq, ack=ack, flags=flags, window=65535
    )
    return p / Raw(load=payload) if payload else p


def spacket(seq, ack, flags, payload=b""):
    p = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(
        sport=SERVER_PORT, dport=CLIENT_PORT, seq=seq, ack=ack, flags=flags, window=65535
    )
    return p / Raw(load=payload) if payload else p


client_packet = cpacket
server_packet = spacket


greeting = b"* OK IMAP ready\r\n"
request = b"A1 FETCH 1:* BODY[]\r\n"
early = b"From: a@example.test\r\nSubject: early\r\n\r\nEARLY-IMAP-MARKER\r\n"
late = b"From: z@example.test\r\nSubject: late\r\n\r\nLATE-IMAP-MARKER\r\n"
padding = b"X" * (30000 - len(early))
body = early + padding
responses = [
    b"* %d FETCH (BODY[] {%d}\r\n%s)\r\n" % (i, len(body), body)
    for i in range(1, 401)
]
responses.append(b"* 99 FETCH (BODY[] {%d}\r\n%s)\r\n" % (len(late), late))
responses.append(b"A1 OK FETCH completed\r\n")

cs, ss = 1000, 9000
packets = [
    cpacket(cs, 0, "S"),
    spacket(ss, cs + 1, "SA"),
    cpacket(cs + 1, ss + 1, "A"),
    spacket(ss + 1, cs + 1, "PA", greeting),
    cpacket(cs + 1, ss + 1 + len(greeting), "PA", request),
]
server_seq = ss + 1 + len(greeting)
for chunk in responses:
    packets.append(spacket(server_seq, cs + 1 + len(request), "PA", chunk))
    server_seq += len(chunk)
    packets.append(cpacket(cs + 1 + len(request), server_seq, "A"))
packets += [
    client_packet(cs + 1 + len(request), server_seq, "PA", b"A2 NOOP\r\n"),
    server_packet(server_seq, cs + 1 + len(request) + len(b"A2 NOOP\r\n"), "PA", b"A2 OK NOOP completed\r\n"),
]
for timestamp, p in enumerate(packets, 1):
    p.time = timestamp
wrpcap("input.pcap", packets)
