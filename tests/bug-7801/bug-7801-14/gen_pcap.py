#!/usr/bin/env python3
"""Generate PCAP for unidirectional split-packet combined byte_extract + byte_math test.

Unidirectional analog of bidirectional test 04: both byte_extract and byte_math
appear in the producer buffer, testing that ALL cached variable slots survive the
cross-packet gap (not just one). If either save path is broken the test fails.

Rule (to_client, unidirectional):
  http.stat_code; byte_extract:3,0,base,string,dec;
                  byte_math:bytes 3,0,+,base,total,string,dec;
  file.data;      byte_test:3,=,total,0,string,dec;

  Status "200": base=200, total=200+200=400; body "400" -> 400==400 -> ALERT
  Status "404": base=404, total=404+404=808; body "000" ->   0!=808 -> no alert

Packet sequence:
  1. Conn1 HTTP request
  2. Conn1 response HEADERS only  -> http.stat_code: base=200, total=400
                                      file.data: no body yet
  3. Conn2 full request + response -> http.stat_code: base=404, total=808
                                       clobbers both byte_values slots
                                       file.data: 0 != 808, no alert
  4. Conn1 response BODY "400"    -> file.data fires
     Without cache: total=808, 400 != 808 -> 0 alerts (BUG)
     With cache:    total=400, 400 == 400 -> 1 alert (CORRECT)

Expected result with fix: 1 alert (Conn1 only).
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

# Status "200": byte_extract base=200, byte_math 200+200=400 (total=400)
# Body "400": byte_test 400==400 -> ALERT
c1_resp_headers = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
)
c1_resp_body = b"400"

c2_req = (
    b"GET /spoil HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# Status "404": base=404, total=808; body "000" -> 0!=808 -> no alert
# Clobbers det_ctx->byte_values[0]=404 and byte_values[1]=808
c2_resp = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
    b"000"
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

# Conn1: server sends HEADERS ONLY
# http.stat_code fires: byte_extract base=200, byte_math total=400
# file.data cannot fire (no body)
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "A",  c1d, c1s, c1_resp_headers))
c1d += len(c1_resp_headers)
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d))

# --- Conn2 handshake + full request/response (spoiler) ---
c2s, c2d = 3000, 4000
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "S",  c2s, 0))
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "SA", c2d, c2s + 1))
c2s += 1; c2d += 1
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d))

pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "PA", c2s, c2d, c2_req))
c2s += len(c2_req)
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "A",  c2d, c2s))

# Spoiler: full response (headers + body together)
# Clobbers det_ctx->byte_values[0]=404 (base) and byte_values[1]=808 (total)
# file.data: "000"=0 != 808 -> no alert
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "PA", c2d, c2s, c2_resp))
c2d += len(c2_resp)
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d))

# Conn2 teardown
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "FA", c2d, c2s))
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d + 1))

# --- Conn1: server sends BODY ---
# file.data fires here.
# Without cache: total=808 (clobbered), 400 != 808 -> no alert (BUG)
# With cache:    total=400 (restored),  400 == 400 -> ALERT (correct)
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "PA", c1d, c1s, c1_resp_body))
c1d += len(c1_resp_body)
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d))

# Conn1 teardown
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "FA", c1d, c1s))
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d + 1))

wrpcap("input.pcap", pkts)
print(f"Generated input.pcap ({len(pkts)} packets)")
print("Conn1: 200 response split (headers then body '400')")
print("  byte_extract base=200, byte_math 200+200=400")
print("Conn2: 404 spoiler (full response, body '000')")
print("  Clobbers byte_values[0]=404 (base) and byte_values[1]=808 (total)")
print("Expected with fix: 1 alert (Conn1); without fix: 0 alerts")
