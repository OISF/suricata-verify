"""Generate input.pcap for detect-xor-var-key-20.

HTTP POST whose URI is "/CD/app": the byte at offset 1 is 'C' (0x43) and
the byte at offset 2 is 'D' (0x44). The body is "login SECRET " XORed with
0x43, followed by "OTHER" XORed with 0x44.

Two rules each take a different URI byte as their xor:var key. Decoding
the body with 0x43 gives "SECRET" and decoding it with 0x44 gives "OTHER",
so each rule matches only on a body decoded with its own key.
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 12345
DPORT = 80

# URI carries both keys: offset 1 is 0x43 ('C'), offset 2 is 0x44 ('D').
uri = b"/CD/app"

# The first part decodes with 0x43, the second with 0x44.
body = bytes([b ^ 0x43 for b in b"login SECRET "]) + \
    bytes([b ^ 0x44 for b in b"OTHER"])

http_request = (
    b"POST " + uri + b" HTTP/1.1\r\n"
    b"Host: 10.0.0.2\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Length: %d\r\n"
    b"\r\n" % len(body)
) + body

http_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 2\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"OK"
)

client_isn = 100
server_isn = 200

syn = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn, flags="S", window=8192)
syn_ack = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER, dst=CLIENT, id=1, ttl=64) / \
    TCP(sport=DPORT, dport=SPORT, seq=server_isn, ack=client_isn + 1,
        flags="SA", window=8192)
ack = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn + 1, ack=server_isn + 1,
        flags="A", window=8192)

request = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn + 1, ack=server_isn + 1,
        flags="PA", window=8192) / Raw(load=http_request)

ack_req = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER, dst=CLIENT, id=1, ttl=64) / \
    TCP(sport=DPORT, dport=SPORT, seq=server_isn + 1,
        ack=client_isn + 1 + len(http_request), flags="A", window=8192)

response = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER, dst=CLIENT, id=1, ttl=64) / \
    TCP(sport=DPORT, dport=SPORT, seq=server_isn + 1,
        ack=client_isn + 1 + len(http_request), flags="PA",
        window=8192) / Raw(load=http_response)

ack_resp = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT,
        seq=client_isn + 1 + len(http_request),
        ack=server_isn + 1 + len(http_response), flags="A", window=8192)

pkts = [syn, syn_ack, ack, request, ack_req, response, ack_resp]
wrpcap("input.pcap", pkts)
print("Wrote input.pcap")
