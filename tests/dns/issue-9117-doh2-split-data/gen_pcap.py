import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"

def frame(ftype, flags, stream_id, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", stream_id & 0x7FFFFFFF) + payload

def hdr(name, value):
    n, v = name.encode(), value.encode()
    return bytes([0x10, len(n)]) + n + bytes([len(v)]) + v

def request_headers():
    return (hdr(":method", "POST") + hdr(":scheme", "https") +
            hdr(":authority", "dns.example.com") + hdr(":path", "/dns-query") +
            hdr("accept", "application/dns-message") +
            hdr("content-type", "application/dns-message"))

def response_headers():
    return hdr(":status", "200") + hdr("content-type", "application/dns-message")

QNAME = b"\x04evil\x03com\x00"

def dns_query():
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + QNAME + \
        struct.pack(">HH", 1, 1)  # A, IN

def dns_response():
    return (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + QNAME +
            struct.pack(">HH", 1, 1) + b"\xc0\x0c" +
            struct.pack(">HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4]))

MAGIC = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# In both directions the DNS message is carried by a DATA frame without
# END_STREAM, followed by an empty DATA frame with END_STREAM.
client_payloads = [
    MAGIC + frame(0x4, 0, 0, b"") + frame(0x1, 0x4, 1, request_headers()),
    frame(0x0, 0x0, 1, dns_query()),
    frame(0x0, 0x1, 1, b""),
]
server_payloads = [
    frame(0x4, 0, 0, b"") + frame(0x1, 0x4, 1, response_headers()),
    frame(0x0, 0x0, 1, dns_response()),
    frame(0x0, 0x1, 1, b""),
]

def client(**kw):
    return Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=SERVER) / \
        TCP(sport=40000, dport=443, **kw)

def server(**kw):
    return Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER, dst=CLIENT) / \
        TCP(sport=443, dport=40000, **kw)

cseq, sseq = 1000, 2000
pkts = [client(flags="S", seq=cseq, ack=0)]
cseq += 1
pkts.append(server(flags="SA", seq=sseq, ack=cseq))
sseq += 1
pkts.append(client(flags="A", seq=cseq, ack=sseq))
# per-segment ACKs so that every DATA frame gets its own detection pass
for pl in client_payloads:
    pkts.append(client(flags="PA", seq=cseq, ack=sseq) / Raw(pl))
    cseq += len(pl)
    pkts.append(server(flags="A", seq=sseq, ack=cseq))
for pl in server_payloads:
    pkts.append(server(flags="PA", seq=sseq, ack=cseq) / Raw(pl))
    sseq += len(pl)
    pkts.append(client(flags="A", seq=cseq, ack=sseq))
pkts.append(server(flags="FA", seq=sseq, ack=cseq))
sseq += 1
pkts.append(client(flags="FA", seq=cseq, ack=sseq))
cseq += 1
pkts.append(server(flags="A", seq=sseq, ack=cseq))
wrpcap("input.pcap", pkts)
