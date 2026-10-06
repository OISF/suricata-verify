#!/usr/bin/env python3
"""Generate PCAP for unidirectional split-packet false positive prevention test.

Tests the opposite failure mode from bug-7801-11: instead of a missed
detection, a clobbered byte value causes a FALSE POSITIVE on a connection
that should not alert.

Rule (to_client, unidirectional):
  http.stat_code; byte_extract:3,0,code_val,string,dec;
  file.data;      byte_test:3,=,code_val,0,string,dec;

Packet sequence:
  1. Conn1 HTTP request
  2. Conn1 response HEADERS only  -> http.stat_code fires: code_val=404
                                      file.data: no body yet
  3. Conn2 full request + response -> http.stat_code: code_val=200 clobbers det_ctx
                                       file.data: "200"=200 == 200 -> ALERT (Conn2)
  4. Conn1 response BODY "200"    -> file.data fires
     Without cache: code_val=200 (clobbered by Conn2), 200==200 -> 2 alerts (FALSE POSITIVE)
     With cache:    code_val=404 (restored),            200!=404 -> 1 alert (CORRECT)

Expected result with fix: 1 alert (Conn2 only, Conn1 correctly suppressed).
"""
from scapy.all import IP, TCP, Raw, wrpcap

C1_SRC   = "10.0.0.1"
C1_DST   = "10.0.0.2"
C1_SPORT = 40001
C1_DPORT = 80

C2_SRC   = "10.0.0.3"
C2_DST   = "10.0.0.2"
C2_SPORT = 40002
C2_DPORT = 80

c1_req = (
    b"GET /test HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# Status "404" -> code_val=404; body "200" -> byte_test: 200 != 404 -> NO ALERT
# (but without cache, code_val is clobbered to 200 -> false alert)
c1_resp_headers = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
)
c1_resp_body = b"200"

c2_req = (
    b"GET /match HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# Status "200" -> code_val=200 (clobbers det_ctx); body "200" -> 200==200 -> ALERT
c2_resp = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
    b"200"
)

pkts = []

def tcp(src, dst, sport, dport, flags, seq, ack, payload=None):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                    flags=flags, seq=seq, ack=ack)
    if payload:
        p = p / Raw(load=payload)
    return p

# --- Conn1 handshake ---
c1s, c1d = 1000, 2000
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "S",  c1s, 0))
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "SA", c1d, c1s + 1))
c1s += 1; c1d += 1
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d))

# Conn1: client request
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "PA", c1s, c1d, c1_req))
c1s += len(c1_req)
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "A",  c1d, c1s))

# Conn1: server sends HEADERS ONLY (404)
# http.stat_code fires: code_val=404 (saved to TX cache if fix applied)
# file.data cannot fire yet (no body)
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "A",  c1d, c1s, c1_resp_headers))
c1d += len(c1_resp_headers)
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d))

# --- Conn2 handshake + full request/response ---
c2s, c2d = 3000, 4000
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "S",  c2s, 0))
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "SA", c2d, c2s + 1))
c2s += 1; c2d += 1
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d))

pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "PA", c2s, c2d, c2_req))
c2s += len(c2_req)
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "A",  c2d, c2s))

# Conn2 full response: code_val=200 clobbers det_ctx->byte_values[0]
# file.data: "200"=200 == 200 -> ALERT (this is the legitimate alert)
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "PA", c2d, c2s, c2_resp))
c2d += len(c2_resp)
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d))

# Conn2 teardown
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "FA", c2d, c2s))
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d + 1))

# --- Conn1: server sends BODY ---
# file.data fires here.
# Without cache: code_val=200 (clobbered by Conn2), 200==200 -> FALSE POSITIVE (BUG)
# With cache:    code_val=404 (restored),            200!=404 -> no alert (correct)
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "PA", c1d, c1s, c1_resp_body))
c1d += len(c1_resp_body)
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d))

# Conn1 teardown
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "FA", c1d, c1s))
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d + 1))

wrpcap("input.pcap", pkts)
print(f"Generated input.pcap ({len(pkts)} packets)")
print("Conn1: 404 response split (headers then body '200'); should NOT alert")
print("Conn2: 200 full response (body '200'); SHOULD alert (1 legitimate alert)")
print("Expected with fix: 1 alert (Conn2 only); without fix: 2 alerts (false positive on Conn1)")
