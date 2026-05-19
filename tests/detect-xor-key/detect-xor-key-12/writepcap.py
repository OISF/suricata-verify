"""Generate input.pcap for detect-xor-key-12.

HTTP POST body with two independently XOR-keyed sections:

  [0]      key1 = 0x42 (1-byte key for rule 1)
  [1..5]   "hello" XOR 0x42
  [6]      key2 = 0x37 (1-byte key for rule 2)
  [7..11]  "world" XOR 0x37

Rule 1: byte_extract:1,0,key1; xor:offset 1,var "key1"; content:"hello"
Rule 2: byte_extract:1,6,key2; xor:offset 7,var "key2"; content:"world"

Both rules use http.request_body. With correct buffer identity (each variable
key location produces a distinct DetectBufferType), both transforms are applied
independently and both rules fire. Without correct identity, the two rules
would share one buffer type and the second rule would inspect a buffer
transformed with the wrong key.
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 12345
DPORT = 80

key1 = 0x42
key2 = 0x37

body = bytes([key1])
body += bytes([b ^ key1 for b in b"hello"])
body += bytes([key2])
body += bytes([b ^ key2 for b in b"world"])

http_request = (
    b"POST /test HTTP/1.1\r\n"
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
print("Wrote input.pcap")
