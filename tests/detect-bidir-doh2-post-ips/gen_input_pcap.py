#!/usr/bin/env python3
"""Craft a minimal DoH2 (DNS-over-HTTP/2) POST pcap for the
detect-bidir-doh2-post test.

Flow: 10.0.0.1:49152 -> 8.8.4.4:443
  Client: preface+SETTINGS, HEADERS (POST /dns-query, content-type
          application/dns-message), DATA (DNS query for x.example.com, EOS)
  Server: SETTINGS, HEADERS (200), DATA (DNS response for x.example.com, EOS)

The request carries the DoH indicators (content-type application/dns-message +
/dns-query path) so Suricata classifies the flow as DOH2; the DNS query and
response live in the request/response DATA frames. The response echoes the
query name "x.example.com", so a toclient dns.response condition on "x"
matches, while one on "nomatchzzz" does not.

HTTP/2 frames use hand-rolled HPACK "literal header field without indexing"
with static-table names (first byte = static name index, then a raw
length-prefixed value string), which is trivially decodable. tshark is used
only for validation, not crafting.
"""
import struct
from scapy.all import IP, TCP, Raw, wrpcap

CLIENT, SPORT = "10.0.0.1", 49152
SERVER, DPORT = "8.8.4.4", 443
CSEQ0, SSEQ0 = 1000, 5000
QNAME = "x.example.com"

# ---------------- DNS messages ----------------
def dns_name(name):
    out = b""
    for lbl in name.split("."):
        out += bytes([len(lbl)]) + lbl.encode()
    return out + b"\x00"

def dns_query(qname):
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return hdr + dns_name(qname) + struct.pack(">HH", 1, 1)  # A IN

def dns_response(qname, answer_ip=b"\x0a\x00\x00\x01"):
    hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = dns_name(qname) + struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + answer_ip
    return hdr + question + answer

DNS_Q = dns_query(QNAME)
DNS_R = dns_response(QNAME)

# ---------------- HTTP/2 + HPACK ----------------
# Static-table indices for the header names we use (see the HPACK static table
# in rust/src/http2/parser.rs).
NAME_IDX = {":method": 2, ":scheme": 7, ":authority": 1, ":path": 4,
            "content-type": 31, ":status": 8}

def hpack_raw_string(s):
    s = s.encode() if isinstance(s, str) else s
    assert len(s) < 128
    return bytes([len(s)]) + s  # huffman bit 0, length < 128

def hpack_noindex(name, value):
    """HPACK 'literal header field without indexing' with a static-table name:
    the static name index (4-bit prefix + continuation) followed by a raw
    length-prefixed value string."""
    idx = NAME_IDX[name]
    head = bytes([idx]) if idx < 15 else bytes([0x0F, idx - 15])
    return head + hpack_raw_string(value)

def h2_frame(ftype, flags, stream, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
           struct.pack(">I", stream & 0x7FFFFFFF) + payload

def hpack_headers(pairs):
    return b"".join(hpack_noindex(k, v) for k, v in pairs)

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS_EMPTY = h2_frame(0x04, 0x00, 0, b"")

client_headers = hpack_headers([
    (":method", "POST"),
    (":scheme", "https"),
    (":authority", SERVER),
    (":path", "/dns-query"),
    ("content-type", "application/dns-message"),
])
client_hdr_frame = h2_frame(0x01, 0x04, 1, client_headers)      # END_HEADERS
client_data_frame = h2_frame(0x00, 0x01, 1, DNS_Q)             # END_STREAM

server_settings = h2_frame(0x04, 0x00, 0, b"")
server_headers = hpack_headers([
    (":status", "200"),
    ("content-type", "application/dns-message"),
])
server_hdr_frame = h2_frame(0x01, 0x04, 1, server_headers)
server_data_frame = h2_frame(0x00, 0x01, 1, DNS_R)             # END_STREAM

# ---------------- TCP ----------------
pkts = []
cseq, sseq = CSEQ0, SSEQ0
_pktno = [0]

def tcp(src, sport, dst, dport, seq, ack, flags, payload=b""):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                   seq=seq, ack=ack, flags=flags)
    if payload:
        p /= Raw(load=payload)
    _pktno[0] += 1
    p.time = _pktno[0] * 0.001
    pkts.append(p)
    return len(payload)

# handshake
tcp(CLIENT, SPORT, SERVER, 443, cseq, 0, "S");  cseq += 1
tcp(SERVER, 443, CLIENT, SPORT, sseq, cseq, "SA"); sseq += 1
tcp(CLIENT, SPORT, SERVER, 443, cseq, sseq, "A")

# client: preface + SETTINGS
n = tcp(CLIENT, SPORT, SERVER, 443, cseq, sseq, "PA", PREFACE + SETTINGS_EMPTY); cseq += n
# client: HEADERS (POST /dns-query)
n = tcp(CLIENT, SPORT, SERVER, 443, cseq, sseq, "PA", client_hdr_frame); cseq += n
# client: DATA (DNS query, EOS)
n = tcp(CLIENT, SPORT, SERVER, 443, cseq, sseq, "PA", client_data_frame); cseq += n
# server ACK
tcp(SERVER, 443, CLIENT, SPORT, sseq, cseq, "A")
# server: SETTINGS
n = tcp(SERVER, 443, CLIENT, SPORT, sseq, cseq, "PA", server_settings); sseq += n
# server: HEADERS (200)
n = tcp(SERVER, 443, CLIENT, SPORT, sseq, cseq, "PA", server_hdr_frame); sseq += n
# server: DATA (DNS response, EOS)
n = tcp(SERVER, 443, CLIENT, SPORT, sseq, cseq, "PA", server_data_frame); sseq += n
# client ACK
tcp(CLIENT, SPORT, SERVER, 443, cseq, sseq, "A")
# teardown
tcp(CLIENT, SPORT, SERVER, 443, cseq, sseq, "FA"); cseq += 1
tcp(SERVER, 443, CLIENT, SPORT, sseq, cseq, "FA"); sseq += 1
tcp(CLIENT, SPORT, SERVER, 443, cseq, sseq, "A")

wrpcap("input.pcap", pkts)
print("wrote input.pcap with", len(pkts), "packets for", QNAME)
