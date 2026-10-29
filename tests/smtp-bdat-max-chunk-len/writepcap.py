#!/usr/bin/env python
# Chunks are delivered, but the message is never closed by "BDAT <n> LAST":
# the sender moves on to a new envelope instead.
from scapy.all import *

client_mac = "00:01:02:03:04:05"
server_mac = "05:04:03:02:01:00"
client_ip = "192.0.2.1"
server_ip = "192.0.2.2"
sport = 41414
dport = 25

client_seq = 1000
server_seq = 5000

pkts = []


def client(payload=None, flags="PA"):
    global client_seq
    p = (
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client_ip, dst=server_ip)
        / TCP(
            sport=sport,
            dport=dport,
            flags=flags,
            seq=client_seq,
            ack=server_seq,
            window=65535,
        )
    )
    if payload is not None:
        p = p / payload
        client_seq += len(payload)
    if "S" in flags or "F" in flags:
        client_seq += 1
    pkts.append(p)


def server(payload=None, flags="PA"):
    global server_seq
    p = (
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip)
        / TCP(
            sport=dport,
            dport=sport,
            flags=flags,
            seq=server_seq,
            ack=client_seq,
            window=65535,
        )
    )
    if payload is not None:
        p = p / payload
        server_seq += len(payload)
    if "S" in flags or "F" in flags:
        server_seq += 1
    pkts.append(p)


client(flags="S")
server(flags="SA")
client(flags="A")

server("220 mail.example.com ESMTP\r\n")
client(flags="A")
client("EHLO client.example.com\r\n")
server("250-mail.example.com\r\n" "250-8BITMIME\r\n" "250 CHUNKING\r\n")
client(flags="A")


client("MAIL FROM:<alice@example.com>\r\n")
server("250 2.1.0 Ok\r\n")
client(flags="A")
client("RCPT TO:<bob@example.com>\r\n")
server("250 2.1.5 Ok\r\n")
client(flags="A")

# a chunk of more than the whole 32 bit space; no octets can follow it
client("BDAT 4294967295\r\n")
server("552 5.3.4 Message size exceeds limit\r\n")
client(flags="A")

# the sender starts over, and that message must still be inspected
client("MAIL FROM:<carol@example.com>\r\n")
server("250 2.1.0 Ok\r\n")
client(flags="A")
client("RCPT TO:<dave@example.com>\r\n")
server("250 2.1.5 Ok\r\n")
client(flags="A")
client("DATA\r\n")
server("354 End data with <CR><LF>.<CR><LF>\r\n")
client(flags="A")
client(
    "From: carol@example.com\r\n"
    "To: dave@example.com\r\n"
    "Subject: after the impossible chunk\r\n"
    "\r\n"
    "Parsing resumed after the oversized declaration.\r\n"
    ".\r\n"
)
server("250 2.0.0 Ok: queued as ABCDEF\r\n")
client(flags="A")

client("QUIT\r\n")
server("221 2.0.0 Bye\r\n")
client(flags="A")

client(flags="FA")
server(flags="FA")
client(flags="A")

wrpcap("input.pcap", pkts)
