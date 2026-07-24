#!/usr/bin/env python
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


# handshake
client(flags="S")
server(flags="SA")
client(flags="A")

# welcome banner and EHLO; the server must not advertise PIPELINING so
# that entering DATA mode depends on matching the 354 reply to the DATA
# command, not on the immediate pipelined-server shortcut.
server("220 mail.example.com ESMTP\r\n")
client(flags="A")
client("EHLO client.example.com\r\n")
server("250-mail.example.com\r\n" "250-8BITMIME\r\n" "250 CHUNKING\r\n")
client(flags="A")

# malformed BDAT with MAIL FROM, RCPT TO and DATA pipelined behind it in
# a single segment
client(
    "BDAT 5 X\r\n"
    "MAIL FROM:<alice@example.com>\r\n"
    "RCPT TO:<bob@example.com>\r\n"
    "DATA\r\n"
)
server(flags="A")

# the server rejects the malformed command but keeps the session open,
# then answers the pipelined commands in order
server(
    "501 5.5.4 Syntax: BDAT count [LAST]\r\n"
    "250 2.1.0 Ok\r\n"
    "250 2.1.5 Ok\r\n"
    "354 End data with <CR><LF>.<CR><LF>\r\n"
)
client(flags="A")

# message body, only inspected if the 354 above was matched to DATA
client(
    "From: alice@example.com\r\n"
    "To: bob@example.com\r\n"
    "Subject: after the rejected chunk\r\n"
    "\r\n"
    "Still inspected after the rejected BDAT command.\r\n"
    ".\r\n"
)
server(flags="A")
server("250 2.0.0 Ok: queued as ABCDEF\r\n")
client(flags="A")

client("QUIT\r\n")
server("221 2.0.0 Bye\r\n")
client(flags="A")

# close
client(flags="FA")
server(flags="FA")
client(flags="A")

wrpcap("input.pcap", pkts)
