#!/usr/bin/env python3
"""Feed two paced batches of DNS query/response pairs into a pcap FIFO.

Batch 1 runs before the rule reload (the output script caches the Dataset
handle), batch 2 after it. Waiting on the go file keeps the engine alive
across the reload.
"""
import os, struct, sys, time

SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.2"
SPORT = 33333
DPORT = 53

def ip4(s):
    return bytes(int(x) for x in s.split("."))

def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def eth(dst, src, payload):
    return dst + src + struct.pack("!H", 0x0800) + payload

def ipv4(src, dst, payload, ident):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, 17, 0, ip4(src), ip4(dst))
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, 17, csum(hdr),
                       ip4(src), ip4(dst)) + payload

def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

def qname(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"

def dns_query(txid, name):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", 1, 1)

def dns_response(txid, name):
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + ip4("10.0.0.2")
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + qname(name) + struct.pack("!HH", 1, 1) + answer

def main():
    fifo, ready, go = sys.argv[1], sys.argv[2], sys.argv[3]
    out = open(fifo, "wb", buffering=0)
    out.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    ts = 0.0

    def batch(start, count):
        nonlocal ts
        for i in range(start, start + count):
            for resp in (0, 1):
                if resp:
                    f = eth(b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02",
                            ipv4(DST_IP, SRC_IP, udp(DPORT, SPORT,
                                                      dns_response(i & 0xFFFF, "q%d.example.com" % i)), i & 0xFFFF))
                else:
                    f = eth(b"\x02\x00\x00\x00\x00\x02", b"\x02\x00\x00\x00\x00\x01",
                            ipv4(SRC_IP, DST_IP, udp(SPORT, DPORT,
                                                     dns_query(i & 0xFFFF, "q%d.example.com" % i)), i & 0xFFFF))
                sec = int(ts)
                usec = int(round((ts - sec) * 1000000))
                out.write(struct.pack("!IIII", sec, usec, len(f), len(f)))
                out.write(f)
                ts += 0.001

    batch(0, 200)
    open(ready, "w").write("ready\n")
    while not os.path.exists(go):
        time.sleep(0.05)
    batch(200, 200)
    time.sleep(0.2)
    out.close()

if __name__ == "__main__":
    main()
