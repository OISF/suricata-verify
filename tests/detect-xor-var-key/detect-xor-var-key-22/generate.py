"""Generate input.pcap for detect-xor-var-key-22.

HTTP POST whose URI is "/CD/app" (byte at offset 1 is 'C' = 0x43, the XOR
key) and whose body is "login SECRET token=1" XORed with 0x43. The request
line and headers go in one TCP segment and the body in a second one, so
the URI is inspected on an earlier packet than the body.
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 12345
DPORT = 80

# URI carries the key material: offset 1 is the key (0x43 = 'C'); offset 2
# (0x44 = 'D') is the key + 1, so a byte_math 'subtract 1' recovers the key.
uri = b"/CD/app"

# Body: the 1-byte key 0x43 is recovered from the URI, not embedded here.
xor_key = 0x43
plaintext = b"login SECRET token=1"
body = bytes([b ^ xor_key for b in plaintext])

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

hdr_len = len(http_request) - len(body)
request_hdr = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn + 1, ack=server_isn + 1,
        flags="PA", window=8192) / Raw(load=http_request[:hdr_len])
ack_hdr = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src=SERVER, dst=CLIENT, id=1, ttl=64) / \
    TCP(sport=DPORT, dport=SPORT, seq=server_isn + 1,
        ack=client_isn + 1 + hdr_len, flags="A", window=8192)
request_body = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn + 1 + hdr_len, ack=server_isn + 1,
        flags="PA", window=8192) / Raw(load=http_request[hdr_len:])

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

pkts = [syn, syn_ack, ack, request_hdr, ack_hdr, request_body, ack_req, response, ack_resp]
wrpcap("input.pcap", pkts)
print("Wrote input.pcap")
