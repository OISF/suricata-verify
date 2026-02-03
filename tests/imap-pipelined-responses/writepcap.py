#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap


CLIENT_IP = "192.0.2.61"
SERVER_IP = "192.0.2.62"
CLIENT_MAC = "02:00:00:00:00:61"
SERVER_MAC = "02:00:00:00:00:62"
CLIENT_PORT = 40643
SERVER_PORT = 143


def packet(server, seq, ack, flags, payload=b""):
    if server:
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_port, dst_port = SERVER_PORT, CLIENT_PORT
    else:
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_port, dst_port = CLIENT_PORT, SERVER_PORT

    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=65535,
        )
    )
    return pkt / Raw(load=payload) if payload else pkt


message = (
    b"From: pipeline@example.test\r\n"
    b"Subject: Pipelined FETCH\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"PIPELINED-FETCH-BODY\r\n"
)

reverse_message = (
    b"From: reverse@example.test\r\n"
    b"Subject: Reverse pipeline\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"REVERSE-PIPELINE-BODY\r\n"
)

ambiguous_message = (
    b"From: ambiguous@example.test\r\n"
    b"Subject: Ambiguous pipeline\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"AMBIGUOUS-FETCH-BODY\r\n"
)

select_pipeline = b"A1 SELECT INBOX\r\nA2 NOOP\r\n"
select_responses = (
    b"* FLAGS (\\Seen)\r\n"
    b"* 3 EXISTS\r\n"
    b"* OK [UIDVALIDITY 42] selected\r\n"
    b"A1 OK [READ-WRITE] SELECT completed\r\n"
    b"A2 OK NOOP completed\r\n"
)

fetch_pipeline = b"A3 FETCH 1 BODY[]\r\nA4 NOOP\r\n"
fetch_responses = (
    b"* 1 FETCH (BODY[] {%d}\r\n" % len(message)
    + message
    + b")\r\n"
    + b"A3 OK FETCH completed\r\n"
    + b"A4 OK NOOP completed\r\n"
)

reverse_pipeline = b"A5 NOOP\r\nA6 FETCH 2 BODY[]\r\n"
reverse_responses = (
    b"* 2 FETCH (BODY[] {%d}\r\n" % len(reverse_message)
    + reverse_message
    + b")\r\n"
    + b"A6 OK FETCH completed\r\n"
    + b"A5 OK NOOP completed\r\n"
)

ambiguous_pipeline = b"A7 FETCH 3 BODY[]\r\nA8 FETCH 4 BODY[]\r\n"
ambiguous_responses = (
    b"* 4 FETCH (BODY[] {%d}\r\n" % len(ambiguous_message)
    + ambiguous_message
    + b")\r\n"
    + b"A8 OK FETCH completed\r\n"
    + b"A7 OK FETCH completed\r\n"
)

# A UID STORE pipelined with a NOOP: its 300 untagged FETCH responses fit
# neither command, and arrive in one chunk.
store_pipeline = b"A9 UID STORE 1:300 +FLAGS (\\Seen)\r\nA10 NOOP\r\n"
store_responses = (
    b"".join(b"* %d FETCH (UID %d FLAGS (\\Seen))\r\n" % (n, n) for n in range(1, 301))
    + b"A9 OK STORE completed\r\n"
    + b"A10 OK NOOP completed\r\n"
)

# Two pipelined LISTs: their untagged responses fit neither command, and the
# second one ends with a literal that continues in the next segment.
list_pipeline = b'L1 LIST "" *\r\nL2 LIST "" %\r\n'
list_responses = [
    b'* LIST () "/" INBOX\r\n* LIST () "/" {6}\r\nfol',
    b"der\r\nL1 OK LIST completed\r\nL2 OK LIST completed\r\n",
]

# Two pipelined UID FETCHes: their body responses fit neither command, each
# ends in a literal, and all arrive in one chunk.
uid_fetch_pipeline = (
    b"U1 UID FETCH 1:* BODY.PEEK[]\r\nU2 UID FETCH 1:* BODY.PEEK[HEADER]\r\n"
)
uid_fetch_body = b"Subject: pipelined\r\n\r\nUID-FETCH-BODY\r\n"
uid_fetch_responses = (
    b"".join(
        b"* %d FETCH (UID %d BODY[] {%d}\r\n" % (n, n, len(uid_fetch_body))
        + uid_fetch_body
        + b")\r\n"
        for n in range(1, 301)
    )
    + b"U1 OK FETCH completed\r\n"
    + b"U2 OK FETCH completed\r\n"
)

client_seq, server_seq = 1000, 9000
greeting = b"* OK IMAP ready\r\n"
packets = [
    packet(False, client_seq, 0, "S"),
    packet(True, server_seq, client_seq + 1, "SA"),
    packet(False, client_seq + 1, server_seq + 1, "A"),
]
client_seq += 1
server_seq += 1

packets.append(packet(True, server_seq, client_seq, "PA", greeting))
server_seq += len(greeting)
packets.append(packet(False, client_seq, server_seq, "PA", select_pipeline))
client_seq += len(select_pipeline)
packets.append(packet(True, server_seq, client_seq, "PA", select_responses))
server_seq += len(select_responses)
packets.append(packet(False, client_seq, server_seq, "PA", fetch_pipeline))
client_seq += len(fetch_pipeline)
packets.append(packet(True, server_seq, client_seq, "PA", fetch_responses))
server_seq += len(fetch_responses)
packets.append(packet(False, client_seq, server_seq, "PA", reverse_pipeline))
client_seq += len(reverse_pipeline)
packets.append(packet(True, server_seq, client_seq, "PA", reverse_responses))
server_seq += len(reverse_responses)
packets.append(packet(False, client_seq, server_seq, "PA", ambiguous_pipeline))
client_seq += len(ambiguous_pipeline)
packets.append(packet(True, server_seq, client_seq, "PA", ambiguous_responses))
server_seq += len(ambiguous_responses)
packets.append(packet(False, client_seq, server_seq, "PA", store_pipeline))
client_seq += len(store_pipeline)
packets.append(packet(True, server_seq, client_seq, "PA", store_responses))
server_seq += len(store_responses)
packets.append(packet(False, client_seq, server_seq, "PA", list_pipeline))
client_seq += len(list_pipeline)
for chunk in list_responses:
    packets.append(packet(True, server_seq, client_seq, "PA", chunk))
    server_seq += len(chunk)
    packets.append(packet(False, client_seq, server_seq, "A"))
packets.append(packet(False, client_seq, server_seq, "PA", uid_fetch_pipeline))
client_seq += len(uid_fetch_pipeline)
packets.append(packet(True, server_seq, client_seq, "PA", uid_fetch_responses))
server_seq += len(uid_fetch_responses)
packets.append(packet(False, client_seq, server_seq, "A"))

for timestamp, pkt in enumerate(packets, 1):
    pkt.time = timestamp

wrpcap("input.pcap", packets)
