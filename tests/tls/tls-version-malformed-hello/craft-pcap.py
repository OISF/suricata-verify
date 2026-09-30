#!/usr/bin/env python3
"""
Craft a pcap with two TLS flows:

  Flow A (10.0.2.5:4444 -> 172.16.0.10:443): a *malformed* ClientHello whose
    legacy version field says 0x0303 (TLS 1.2) but whose extensions length is
    bogus (0xffff with no extension bytes), so the hello decode fails and the
    phase advance is suppressed. A following application-data record advances
    the track to the data phase anyway.

  Flow B (10.0.2.6:4445 -> 172.16.0.11:443): a *valid* ClientHello with
    version 0x0303, followed by application data (the control).

tls.version must only match a version that was actually decoded from a hello.
Flow A's hello never decoded, so `tls.version:1.2` must NOT alert on it; flow
B's hello decoded, so the control rule must alert. Before the fix the decoded
test was "the track moved past the hello state", which flow A satisfies via
the application-data record, so `tls.version:1.2` matched an undecoded flow.

  P1-P3  Flow A TCP 3-way handshake
  P4     Flow A client->server TLS record (handshake) = malformed ClientHello
  P5     Flow A server ACK
  P6     Flow A client->server TLS record (application data)
  P7     Flow A server ACK
  P8-P10 Flow B TCP 3-way handshake
  P11    Flow B client->server TLS record (handshake) = valid ClientHello
  P12    Flow B server ACK
  P13    Flow B client->server TLS record (application data)
  P14    Flow B server ACK

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import socket
import struct

DST = "input.pcap"

MAC_C = bytes.fromhex("aabbccddee01")
MAC_S = bytes.fromhex("aabbccddee02")

# ClientHello body: version 0x0303 (TLS 1.2), random, empty session id,
# one cipher suite, null compression, then the extensions length.
def hello_body(ext_len):
    return (struct.pack(">H", 0x0303) + b"\x11" * 32 + b"\x00" +
            struct.pack(">H", 2) + b"\x00\x2f" + b"\x01\x00" +
            struct.pack(">H", ext_len))


VALID_BODY = hello_body(0x0000)
MALFORMED_BODY = hello_body(0xffff)
assert len(VALID_BODY) == 43 and len(MALFORMED_BODY) == 43


def hs_hello(body):
    return struct.pack(">B", 1) + struct.pack(">I", len(body))[1:] + body


def csum16(buf):
    if len(buf) % 2:
        buf += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(buf) // 2), buf))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def ip_pkt(src, dst, payload, ip_id, mac_s, mac_d):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0, 64,
                      socket.IPPROTO_TCP, 0, socket.inet_aton(src),
                      socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack(">H", csum16(hdr)) + hdr[12:]
    return mac_d + mac_s + b"\x08\x00" + hdr + payload


def tcp_pkt(src, dst, seq, ack, flags, payload):
    hdr = struct.pack(">HHIIBBHHH", src, dst, seq, ack, (5 << 4), flags,
                      65535, 0, 0)
    hdr = hdr[:16] + struct.pack(">H", csum16(hdr + payload)) + hdr[18:]
    return hdr + payload


def tls_record(rtype, version, body):
    return struct.pack(">BHH", rtype, version, len(body)) + body


def main():
    pkts = []
    ip_id = 1

    def send(src_ip, dst_ip, sport, dport, seq, ack, flags, payload):
        nonlocal ip_id
        pkts.append(ip_pkt(src_ip, dst_ip,
                           tcp_pkt(sport, dport, seq, ack, flags, payload),
                           ip_id,
                           MAC_C if src_ip.startswith("10.") else MAC_S,
                           MAC_S if src_ip.startswith("10.") else MAC_C))
        ip_id += 1

    def flow(client_ip, server_ip, sport, dport, cseq, sseq, hello):
        send(client_ip, server_ip, sport, dport, cseq, 0, 0x02, b"")
        send(server_ip, client_ip, dport, sport, sseq, cseq + 1, 0x12, b"")
        send(client_ip, server_ip, sport, dport, cseq + 1, sseq + 1, 0x10, b"")
        rec = tls_record(22, 0x0301, hello)
        send(client_ip, server_ip, sport, dport, cseq + 1, sseq + 1, 0x18, rec)
        send(server_ip, client_ip, dport, sport, sseq + 1, cseq + 1 + len(rec),
             0x10, b"")
        # application data advances the track to the data phase
        app = tls_record(23, 0x0303, b"\xaa" * 8)
        send(client_ip, server_ip, sport, dport, cseq + 1 + len(rec), sseq + 1,
             0x18, app)
        send(server_ip, client_ip, dport, sport, sseq + 1,
             cseq + 1 + len(rec) + len(app), 0x10, b"")

    flow("10.0.2.5", "172.16.0.10", 4444, 443, 1000, 5000,
         hs_hello(MALFORMED_BODY))
    flow("10.0.2.6", "172.16.0.11", 4445, 443, 2000, 6000,
         hs_hello(VALID_BODY))

    with open(DST, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)))
            f.write(p)
    print("wrote %s with %d packets" % (DST, len(pkts)))


if __name__ == "__main__":
    main()
