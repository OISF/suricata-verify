#!/usr/bin/env python3
"""Generate the TFTP single-direction-transaction test pcap.

Synthetic, hand-built with the Python standard library only.  Nothing here was
captured from any network.  Derived from the generator used for the original
report (mkpcap130.py); trimmed to the smallest shape that exercises the defect.

Shape (one UDP flow, 10.0.0.2:40000 <-> 10.0.0.1:69):
    N x RFC 1350 Read Request, client -> server
    1 x RFC 1350 ERROR, server -> client, FROM PORT 69

The server-side ERROR is sent from port 69 rather than from a freshly allocated
transfer TID.  A server that refuses outright, without allocating a transfer
TID, answers from 69, and that is what puts a to-client packet on the same
5-tuple as the request (reversed, so the same flow) -- which is what makes the
to-client inspection of the request
transaction observable.
"""
import struct, sys, os

def ipv4_cksum(b):
    if len(b) % 2:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def frame(src_ip, dst_ip, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes(int(x) for x in src_ip.split(".")),
                     bytes(int(x) for x in dst_ip.split(".")))
    ip = ip[:10] + struct.pack("!H", ipv4_cksum(ip)) + ip[12:]
    return (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
            + b"\x08\x00" + ip + udp)

def write_pcap(path, frames, usec_step=1000):
    # classic libpcap, microsecond timestamps, no extensions (pcap-check.sh)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        ts, us = 1750000000, 0
        for fr in frames:
            f.write(struct.pack("<IIII", ts, us, len(fr), len(fr)))
            f.write(fr)
            us += usec_step
            while us >= 1000000:
                us -= 1000000
                ts += 1

def rrq(name=b"rfc1350.txt"):
    # opcode 1 (RRQ) | filename \0 | "octet" \0
    return b"\x00\x01" + name + b"\x00" + b"octet" + b"\x00"

def error(code=1, msg=b"File not found"):
    # opcode 5 (ERROR) | error code | message \0
    return b"\x00\x05" + struct.pack("!H", code) + msg + b"\x00"

CLIENT, SERVER = "10.0.0.2", "10.0.0.1"
CPORT, SPORT = 40000, 69

def build(n_rrq):
    frames = [frame(CLIENT, SERVER, CPORT, SPORT, rrq()) for _ in range(n_rrq)]
    frames.append(frame(SERVER, CLIENT, SPORT, CPORT, error()))
    return frames

if __name__ == "__main__":
    out = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    frames = build(n)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    write_pcap(out, frames)
    print("%s: %d frames (%d RRQ + 1 server ERROR), frame sizes %s, %d bytes on disk"
          % (out, len(frames), n, sorted(set(len(f) for f in frames)),
             os.path.getsize(out)))
