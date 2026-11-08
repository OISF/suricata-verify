#!/usr/bin/env python3
"""Generate PCAP for a byte value produced on a pass that resumes stored state.

Rule (=>): http.uri matches "/r/", http.stat_code produces code_val, file.data
checks its body against code_val.

  1. Conn1 request           toserver pass: http.uri matches, nothing produced
                             yet, inspect state stored
  2. Conn1 response HEADERS  toclient pass resumes that state: http.stat_code
                             produces code_val = 200, file.data has no body yet
  3. Conn2, complete         produces code_val = 404 on the same thread; its body
                             "000" does not match, no alert
  4. Conn1 response BODY     toclient pass resumes again: file.data checks "200"

In tests 09 to 12 the producer runs on the pass that first stores state for the
signature. Here state already exists when it runs, so the value has to be kept
when the stored state is updated, not only when it is created.

Without per-transaction values: Conn1 compares "200" with 404, 0 alerts.
With them:                      1 alert, on Conn1.
"""
from scapy.all import IP, TCP, Raw, wrpcap

# Connection 1 - the target connection (split response)
C1_SRC  = "10.0.0.1"
C1_DST  = "10.0.0.2"
C1_SPORT = 40181
C1_DPORT = 80

# Connection 2 - the spoiler connection (full response in one packet)
C2_SRC  = "10.0.0.3"
C2_DST  = "10.0.0.2"
C2_SPORT = 40182
C2_DPORT = 80

c1_req = (
    b"GET /r/one HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# Response split into headers-only first, body second.
# Status code "200" -> code_val = 200.
# Body is "200" -> byte_test: "200" as decimal = 200 == code_val=200 -> ALERT.
c1_resp_headers = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 3\r\n"
    b"\r\n"
)
c1_resp_body = b"200"

c2_req = (
    b"GET /r/two HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# Spoiler full response: status 404, body "000".
# code_val would be 404; byte_test: "000"=0 != 404 -> no alert.
# This clobbers det_ctx->byte_values[0] = 404.
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

# Conn1: server sends HEADERS ONLY (no body yet).
# http.stat_code engine fires here: code_val = 200.
# file.data engine cannot fire yet (body not arrived).
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "A",  c1d, c1s, c1_resp_headers))
c1d += len(c1_resp_headers)
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d))
# A toclient packet with nothing new in it. Acked data is inspected on the next
# packet in its direction, so without this one the headers would first be
# inspected together with the body, after the other connection has come and gone.
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "A",  c1d, c1s))

# --- Conn2 handshake + full request/response (spoiler) ---
c2s, c2d = 3000, 4000
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "S",  c2s, 0))
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "SA", c2d, c2s + 1))
c2s += 1; c2d += 1
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d))

pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "PA", c2s, c2d, c2_req))
c2s += len(c2_req)
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "A",  c2d, c2s))

# Spoiler: full response (headers + body together).
# http.stat_code fires: clobbers det_ctx->byte_values[0] = 404.
# file.data fires: "000"=0 != 404 -> no alert for Conn2.
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "PA", c2d, c2s, c2_resp))
c2d += len(c2_resp)
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d))

# Conn2 teardown
pkts.append(tcp(C2_DST, C2_SRC, C2_DPORT, C2_SPORT, "FA", c2d, c2s))
pkts.append(tcp(C2_SRC, C2_DST, C2_SPORT, C2_DPORT, "A",  c2s, c2d + 1))

# --- Conn1: server sends BODY ---
# file.data engine fires here.
# Without cache: code_val = 404 (clobbered by Conn2), "200"=200 != 404 -> no alert (BUG).
# With cache:    code_val = 200 (restored),            "200"=200 == 200 -> ALERT (correct).
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "PA", c1d, c1s, c1_resp_body))
c1d += len(c1_resp_body)
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d))

# Conn1 teardown
pkts.append(tcp(C1_DST, C1_SRC, C1_DPORT, C1_SPORT, "FA", c1d, c1s))
pkts.append(tcp(C1_SRC, C1_DST, C1_SPORT, C1_DPORT, "A",  c1s, c1d + 1))

wrpcap("input.pcap", pkts)
print(f"Generated input.pcap ({len(pkts)} packets)")
print("Conn1: 200 response split across two packets (headers then body)")
print("Conn2: 404 spoiler (full response) arrives between Conn1 header and body packets")
print("Expected with fix: 1 alert (Conn1); without fix: 0 alerts")
