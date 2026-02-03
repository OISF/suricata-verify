#!/usr/bin/env python3
from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_IP, SERVER_IP = "192.0.2.41", "192.0.2.42"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:41", "02:00:00:00:00:42"
CPORT, SPORT = 40443, 143


def packet(server, seq, ack, flags, payload=b"", cport=CPORT):
    if server:
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_port, dst_port = SPORT, cport
    else:
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_port, dst_port = cport, SPORT
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags)
    )
    return pkt / Raw(load=payload) if payload else pkt


requests = [b"A1 NOOP\r\n", b"A2 NOOP\r\n", b"A3 NOOP\r\n"]
client_seq, server_seq = 1000, 9000
client_data_seq = client_seq + 1
server_data_seq = server_seq + 1
packets = [
    packet(False, client_seq, 0, "S"),
    packet(True, server_seq, client_data_seq, "SA"),
    packet(False, client_data_seq, server_data_seq, "A"),
]

for request in requests:
    packets.append(
        packet(
            False,
            client_data_seq,
            server_data_seq,
            "PA",
            request,
        )
    )
    client_data_seq += len(request)


# With both transactions live, an invalid client line arrives while a server
# literal is consumed: the literal must survive, including a line in it that
# looks like a tagged reply.
cport = CPORT + 1
client_seq, server_seq = 1000, 9000
body = [b"Subject: x\r\n\r\n", b"A9 OK injected\r\nbody\r\n"]


def send(server, payload):
    global client_seq, server_seq
    if server:
        packets.append(packet(True, server_seq, client_seq, "PA", payload, cport))
        server_seq += len(payload)
    else:
        packets.append(packet(False, client_seq, server_seq, "PA", payload, cport))
        client_seq += len(payload)


packets.append(packet(False, client_seq, 0, "S", cport=cport))
packets.append(packet(True, server_seq, client_seq + 1, "SA", cport=cport))
client_seq += 1
server_seq += 1
send(False, b"")
send(True, b"* OK IMAP ready\r\n")
# Acknowledged both ways, so the greeting is freed before the commands.
send(False, b"")
send(True, b"")
send(False, b"A1 FETCH 1 BODY[]\r\nA2 NOOP\r\n")
send(True, b"* 1 FETCH (BODY[] {%d}\r\n" % len(b"".join(body)) + body[0])
send(False, b"%%%\r\n")
send(True, body[1] + b")\r\nA1 OK FETCH completed\r\nA2 OK NOOP completed\r\n")
send(False, b"")

# With both transactions live, a reply matching no command is dropped rather
# than ending one of them; the event is raised once there is room.
cport = CPORT + 2
client_seq, server_seq = 1000, 9000
packets.append(packet(False, client_seq, 0, "S", cport=cport))
packets.append(packet(True, server_seq, client_seq + 1, "SA", cport=cport))
client_seq += 1
server_seq += 1
send(False, b"")
send(True, b"* OK IMAP ready\r\n")
send(False, b"")
send(True, b"")
send(False, b"B1 NOOP\r\nB2 NOOP\r\n")
send(True, b"B9 OK stray\r\n")
send(False, b"")
send(True, b"B1 OK NOOP completed\r\nB2 OK NOOP completed\r\n")
send(False, b"")
send(True, b"")
send(False, b"B3 NOOP\r\n")
send(True, b"B3 OK NOOP completed\r\n")
send(False, b"")

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
