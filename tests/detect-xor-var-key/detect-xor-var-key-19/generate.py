"""Generate input.pcap for detect-xor-var-key-19.

Coexistence of the two variable-key mechanisms on the same buffer: an
in-buffer `extract` key and a `byte_extract` `var` key. The two produce
distinct inspection buffers (their dedup ids carry different discriminants),
so both rules run and both alert.

The URI is "/CD/app" (offset 1 is 'C' = 0x43, read by byte_extract for the
var-key rule). The body is the key byte 0x43 followed by
"login SECRET token=1" encrypted with 0x43:

  * the extract rule `xor:offset 1,extract 1 0` reads the key from body
    offset 0 (0x43) and decodes from offset 1; and
  * the var rule reads the same key value 0x43 from the URI and decodes the
    whole body (the leading 0x43 XORs to 0x00, the rest to the plaintext).

Both therefore recover "SECRET".
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 12345
DPORT = 80

# URI offset 1 holds the key (0x43 = 'C'); the same value is embedded at body
# offset 0 for the in-buffer extract rule.
uri = b"/CD/app"

xor_key = 0x43
plaintext = b"login SECRET token=1"
body = bytes([xor_key]) + bytes([b ^ xor_key for b in plaintext])

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
