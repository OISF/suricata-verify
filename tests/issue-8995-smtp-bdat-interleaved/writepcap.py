#!/usr/bin/env python3
from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_MAC = "00:01:02:03:04:05"
SERVER_MAC = "05:04:03:02:01:00"
CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
SPORT = 41414
DPORT = 25

client_seq = 1000
server_seq = 5000
pkts = []


def client(payload=None, flags="PA"):
    global client_seq
    p = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=SPORT,
            dport=DPORT,
            flags=flags,
            seq=client_seq,
            ack=server_seq,
            window=65535,
        )
    )
    if payload is not None:
        data = payload.encode() if isinstance(payload, str) else payload
        p /= Raw(data)
        client_seq += len(data)
    if "S" in flags or "F" in flags:
        client_seq += 1
    pkts.append(p)


def server(payload=None, flags="PA"):
    global server_seq
    p = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=DPORT,
            dport=SPORT,
            flags=flags,
            seq=server_seq,
            ack=client_seq,
            window=65535,
        )
    )
    if payload is not None:
        data = payload.encode() if isinstance(payload, str) else payload
        p /= Raw(data)
        server_seq += len(data)
    if "S" in flags or "F" in flags:
        server_seq += 1
    pkts.append(p)


def client_data(payload):
    client(payload)
    server(flags="A")


def server_data(payload):
    server(payload)
    client(flags="A")


message = (
    "From: alice@example.com\r\n"
    "To: bob@example.com\r\n"
    "Subject: inspected after interleaved BDAT replies\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/mixed; boundary="boundary"\r\n'
    "\r\n"
    "--boundary\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "The attachment must still be inspected.\r\n"
    "--boundary\r\n"
    'Content-Type: application/octet-stream; name="eicar.txt"\r\n'
    'Content-Disposition: attachment; filename="eicar.txt"\r\n'
    "Content-Transfer-Encoding: 7bit\r\n"
    "\r\n"
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n"
    "--boundary--\r\n"
    ".\r\n"
)

# TCP handshake.
client(flags="S")
server(flags="SA")
client(flags="A")

server_data("220 mail.example.com ESMTP ready\r\n")
client_data("EHLO client.example.com\r\n")
server_data(
    "250-mail.example.com\r\n"
    "250-PIPELINING\r\n"
    "250 CHUNKING\r\n"
)

# Start transaction 0.
client_data("MAIL FROM:<first@example.com>\r\n")
server_data("250 2.1.0 Ok\r\n")
client_data("RCPT TO:<discard@example.com>\r\n")
server_data("250 2.1.5 Ok\r\n")

# The first chunk is complete. The second command and only half of its
# ten-byte payload are already in flight when the first reply arrives.
client_data("BDAT 4\r\nABCDBDAT 10 LAST\r\n12345")
server_data("451 4.3.0 First chunk rejected\r\n")

# RFC 3030 requires the server to drain an already-pipelined chunk after an
# earlier failure. This completes the second payload without a line ending.
client_data("67890")
server_data("503 5.5.1 Transaction failed\r\n")

# This must be parsed as RSET, not joined to the second chunk remainder as
# the bogus command "67890RSET".
client_data("RSET\r\n")
server_data("250 2.0.0 Reset state\r\n")

# Transaction 1 proves synchronization and inspection were preserved.
client_data("MAIL FROM:<alice@example.com>\r\n")
server_data("250 2.1.0 Ok\r\n")
client_data("RCPT TO:<bob@example.com>\r\n")
server_data("250 2.1.5 Ok\r\n")
client_data("DATA\r\n")
server_data("354 End data with <CR><LF>.<CR><LF>\r\n")
client_data(message)
server_data("250 2.0.0 Queued\r\n")
client_data("QUIT\r\n")
server_data("221 2.0.0 Bye\r\n")

client(flags="FA")
server(flags="FA")
client(flags="A")

for i, pkt in enumerate(pkts):
    pkt.time = i
wrpcap("input.pcap", pkts)
