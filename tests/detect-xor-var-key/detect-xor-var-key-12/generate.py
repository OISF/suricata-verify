"""Generate input.pcap for detect-xor-var-key-12.

HTTP POST whose URI is "/CD/app" (byte at offset 1 is 'C' = 0x43, the XOR
key) and whose body is a 4-byte plaintext header "HDR:" followed by
"login SECRET token=1" encrypted with the 1-byte key 0x43.

The rule extracts the key from the URI with byte_extract and decodes the body
with `xor:offset 4,var xkey`: the leading 4 header bytes are copied through
unchanged and XOR decoding starts at offset 4, exercising a decode offset
combined with a variable key.
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 12345
DPORT = 80

# URI offset 1 holds the key (0x43 = 'C').
uri = b"/CD/app"

xor_key = 0x43
header = b"HDR:"  # 4 unchanged bytes preceding the encoded region
plaintext = b"login SECRET token=1"
# Body: unchanged header, then the plaintext encoded with the 1-byte key.
body = header + bytes([b ^ xor_key for b in plaintext])

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
