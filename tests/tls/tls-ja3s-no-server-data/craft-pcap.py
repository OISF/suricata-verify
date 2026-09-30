#!/usr/bin/env python3
"""
Craft the no-server-data ja3s test pcap.

Derives a 13-frame prefix of tests/tls/tls-certs-alert/input.pcap: a
TLS1.2 session (client certificate exchange) that ends right after the
client's flight - the server sends no application data at all.

The point of the session: the TLS event carrying the ja3s field is
emitted once the data phase is reached, not at a flight-completion
milestone. The tracks reach their data phase independently: the
server track through its certificate (a 3999-byte record fragmented
over frames 6-10), the client track through its own
ChangeCipherSpec (frame 12). The event flushes on the packet after
both are in phase - ja3s stays published for a session without
server app data.

Run this script from its own test directory: the pcap is written to
input.pcap.
"""

import os
import struct

SRC = os.path.join("..", "tls-certs-alert", "input.pcap")
DST = "input.pcap"
FRAMES = 13


def main():
    d = open(SRC, "rb").read()
    if d[:4] not in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        raise SystemExit("unexpected pcap magic in %s" % SRC)
    out = bytearray(d[:24])
    off = 24
    n = 0
    while off < len(d) and n < FRAMES:
        ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", d[off:off + 16])
        out += struct.pack("<IIII", ts_sec, ts_usec, incl, orig)
        out += d[off + 16:off + 16 + incl]
        off += 16 + incl
        n += 1
    if n != FRAMES:
        raise SystemExit("source pcap has only %d frames" % n)
    with open(DST, "wb") as f:
        f.write(bytes(out))
    print("wrote %s: %d frames" % (DST, n))


if __name__ == "__main__":
    main()
