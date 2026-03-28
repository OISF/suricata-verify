"""Generate input.pcap for detect-xor-key-14.

HTTP GET request whose URI uses a variable XOR key:

  URI: /[key][encoded data]

  [0]     '/' (the leading slash — not part of key/data)
  [1]     key = 0x30 ('0')
  [2..5]  "path" XOR 0x30 = "@QDX"

Rule: http.uri; xor:offset 2,var 1 1; content:"path"

The transform reads the 1-byte key at URI offset 1, then XORs from
offset 2 onward, decoding "@QDX" back to "path". Verifies the
transform works on http.uri as well as http.request_body.
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 12345
DPORT = 80

key = 0x30
plaintext = b"path"
encoded = bytes(b ^ key for b in plaintext)

# URI: /0@QDX  (leading slash + key byte + 4 encoded bytes)
uri = b"/" + bytes([key]) + encoded

http_request = (
    b"GET " + uri + b" HTTP/1.1\r\n"
    b"Host: 10.0.0.2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

http_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 2\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"OK"
)

client_isn = 100
server_isn = 200

syn = Ether() / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn, flags="S", window=8192)
syn_ack = Ether() / IP(src=SERVER, dst=CLIENT, id=1, ttl=64) / \
    TCP(sport=DPORT, dport=SPORT, seq=server_isn, ack=client_isn + 1,
        flags="SA", window=8192)
ack = Ether() / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn + 1, ack=server_isn + 1,
        flags="A", window=8192)
request = Ether() / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT, seq=client_isn + 1, ack=server_isn + 1,
        flags="PA", window=8192) / Raw(load=http_request)
ack_req = Ether() / IP(src=SERVER, dst=CLIENT, id=1, ttl=64) / \
    TCP(sport=DPORT, dport=SPORT, seq=server_isn + 1,
        ack=client_isn + 1 + len(http_request), flags="A", window=8192)
response = Ether() / IP(src=SERVER, dst=CLIENT, id=1, ttl=64) / \
    TCP(sport=DPORT, dport=SPORT, seq=server_isn + 1,
        ack=client_isn + 1 + len(http_request), flags="PA",
        window=8192) / Raw(load=http_response)
ack_resp = Ether() / IP(src=CLIENT, dst=SERVER, id=1, ttl=64) / \
    TCP(sport=SPORT, dport=DPORT,
        seq=client_isn + 1 + len(http_request),
        ack=server_isn + 1 + len(http_response), flags="A", window=8192)

pkts = [syn, syn_ack, ack, request, ack_req, response, ack_resp]
wrpcap("input.pcap", pkts)
print(f"Wrote input.pcap  URI={uri!r}  key=0x{key:02x}  plaintext={plaintext!r}")
