#!/usr/bin/env python3
from scapy.all import Ether, IP, Raw, TCP, wrpcap

CLIENT_MAC = "00:01:02:03:04:05"
SERVER_MAC = "05:04:03:02:01:00"
CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
SPORT = 41415
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
    "Subject: inspected after shifted BDAT replies\r\n"
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

# Suricata treats the 17 octets after the first BDAT as chunk data, then
# queues the large BDAT and waits for its payload. The early-rejecting
# server instead treats those octets as MAIL FROM and replies to all three
# commands. MAIL FROM's 250 is consequently matched to Suricata's active
# queue-tail BDAT and must end data mode even though it is not an error.
client_data(
    "BDAT 17\r\n"
    "MAIL FROM:<a@b>\r\n"
    "BDAT 1000000\r\n"
)
server_data(
    "503 5.5.1 Need RCPT command\r\n"
    "250 2.1.0 Ok\r\n"
    "503 5.5.1 Need RCPT command\r\n"
)

# Transaction 0 can only be abandoned if the shifted 250 above cleared the
# active BDAT mode.
client_data("RSET\r\n")
server_data("250 2.0.0 Reset state\r\n")

# Transaction 1 proves synchronization and inspection were restored.
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
