#!/usr/bin/env python3
# Generates input.pcap: two plaintext HTTP/2 flows (client 10.20.0.14 ->
# server 142.251.111.105:443) validating the http_client_body app_stream
# registration for http2 (http.request_body keyword, hook
# http2:stream:<request_data).
#
# Each flow sends one request (stream 1) whose 8192-byte body arrives in two
# 4096-byte DATA frames:
# * flow A (port 49230): the marker "HTTP2MARKERABCD1" is in the second DATA
#   frame - the first DATA pass sees a 4096-byte body without the marker; its
#   no-match is provisional (the buffer is streaming) and the rule matches
#   when the second frame completes the body; the flow is accepted.
# * flow B (port 49231): the second DATA frame carries the same-length
#   replacement "NOMATCHDISC12345" instead of the marker; the body never
#   matches, the engine's own eof CANT_MATCH (END_STREAM) rejects the rule
#   and the flow is dropped once.
#
# Expected: exactly 1 `firewall default app policy` drop (flow B).
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "142.251.111.105"  # $HOME_NET -> $EXTERNAL_NET
SP_A, SP_B, DP = 49230, 49231, 443
MARKER = b"HTTP2MARKERABCD1"          # 16 bytes
REPL = b"NOMATCHDISC12345"            # 16 bytes
assert len(MARKER) == len(REPL) == 16

def h2_frame(ftype, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + stream.to_bytes(4, "big") + payload

def hpack_request(path, authority, clen):
    # fresh-connection encodings: static table + new-name literal only
    block = b"\x82"                      # :method GET (static 2)
    block += b"\x43" + bytes([len(path)]) + path          # :path (static 3)
    block += b"\x84"                      # :scheme http (static 4)
    block += b"\x41" + bytes([len(authority)]) + authority  # :authority (static 1)
    block += b"\x40" + b"\x0e" + b"content-length" + bytes([len(clen)]) + clen
    return block

def h2_exchange(sp, body2, pkts):
    cseq, sseq = 1000 + sp, 5000 + sp
    def mk(src, dst, sp, dp, seq, ack, flags, payload=b""):
        p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
                  dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55")/IP(src=src, dst=dst)/TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
        if payload: p = p/Raw(payload)
        return p
    pkts.append(mk(SIP, DIP, sp, DP, cseq - 1, 0, "S"))
    pkts.append(mk(DIP, SIP, DP, sp, sseq - 1, cseq, "SA"))
    cack, sack = sseq, cseq
    def c(payload, flags="PA"):
        nonlocal cseq, cack, sack
        pkts.append(mk(SIP, DIP, sp, DP, cseq, cack, flags, payload))
        cseq += len(payload); sack = cseq
    def s(payload=b"", flags="A"):
        nonlocal sseq, sack, cack
        pkts.append(mk(DIP, SIP, DP, sp, sseq, sack, flags, payload))
        sseq += len(payload); cack = sseq
    c(b"", "A")
    # client preface (no SETTINGS frame: the connection-level (global) tx
    # would be presented to detection before the stream tx and, having no
    # covering rule for the global states, the default app policy would drop
    # the flow before the request body is even parsed; the global tx is
    # deliberately out of scope for this test)
    c(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    s(b"", "A")
    # request headers (no END_STREAM: a body follows)
    c(h2_frame(1, 0x04, 1, hpack_request(b"/upload", b"up.example.com", b"8192")))
    s()
    # body: two 4096-byte DATA frames, then END_STREAM
    c(h2_frame(0, 0, 1, b"A" * 4096))
    s()
    c(h2_frame(0, 0, 1, body2))
    s()
    c(h2_frame(0, 1, 1))      # END_STREAM
    s()
    # clean close
    s(b"", "F")
    sack = sseq + 1
    c(b"", "A")
    c(b"", "F")
    s(b"", "A")

pkts = []
h2_exchange(SP_A, b"B" * 4080 + MARKER, pkts)
h2_exchange(SP_B, b"B" * 4080 + REPL, pkts)
wrpcap("input.pcap", pkts)
print("wrote input.pcap:", len(pkts), "packets")
