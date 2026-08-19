#!/usr/bin/env python3
"""Generate input.pcap for the filestore-fd-exhaustion test.

The pcap contains N concurrent HTTP downloads whose bodies are delivered
round-robin (interleaved) across all flows, so every file is mid-transfer at
the same time. Each file is larger than the file-store incremental-write
threshold (~100 KiB), so file-store writes it out while it is still open and,
on builds that keep the descriptor open, holds one fd per concurrent file.
With force-filestore and a low fd ulimit this exhausts the process fd table.

Each body carries a per-flow marker so the files have distinct SHA-256s and are
not collapsed by file-store de-duplication.

Regenerate:  ./generate-pcap.py -o input.pcap
"""

import argparse

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

N = 48              # concurrent flows (must exceed the ulimit used in test.yaml)
FILE_SIZE = 131072  # > ~100 KiB so each file is written incrementally
CHUNK = 8192        # body bytes per flow per interleave round
CMAC, SMAC = "02:00:00:00:00:01", "02:00:00:00:00:02"


def body(flow_id, off, length):
    data = bytearray(b"A" * length)
    marker = ("flow=%020d\n" % flow_id).encode()
    if off < len(marker):
        n = min(length, len(marker) - off)
        data[:n] = marker[off:off + n]
    return bytes(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=N)
    ap.add_argument("-o", "--output", default="input.pcap")
    a = ap.parse_args()

    w = PcapWriter(a.output, sync=True)
    t = [1.0]

    def wr(p):
        p.time = t[0]
        t[0] += 1e-6
        w.write(p)

    flows = []
    for i in range(a.n):
        f = dict(id=i + 1, cip="10.0.%d.%d" % ((i >> 8) & 0xff, i & 0xff),
                 sip="10.9.0.1", cp=1024 + (i % 60000), sp=80,
                 cs=(0x1000 + i * 8191) & 0xffffffff,
                 ss=(0x9000 + i * 104729) & 0xffffffff, sent=0)
        flows.append(f)

    def pkt(f, d, flags, seq, ack=0, pl=b""):
        if d == "c":
            e = Ether(src=CMAC, dst=SMAC) / IP(src=f["cip"], dst=f["sip"])
            tcp = TCP(sport=f["cp"], dport=f["sp"], flags=flags, seq=seq, ack=ack, window=65535)
        else:
            e = Ether(src=SMAC, dst=CMAC) / IP(src=f["sip"], dst=f["cip"])
            tcp = TCP(sport=f["sp"], dport=f["cp"], flags=flags, seq=seq, ack=ack, window=65535)
        p = e / tcp
        return p / Raw(pl) if pl else p

    # Handshake + request + response headers for every flow first.
    for f in flows:
        wr(pkt(f, "c", "S", f["cs"])); f["cs"] = (f["cs"] + 1) & 0xffffffff
        wr(pkt(f, "s", "SA", f["ss"], f["cs"])); f["ss"] = (f["ss"] + 1) & 0xffffffff
        wr(pkt(f, "c", "A", f["cs"], f["ss"]))
        req = ("GET /f%d.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % f["id"]).encode()
        wr(pkt(f, "c", "PA", f["cs"], f["ss"], req)); f["cs"] = (f["cs"] + len(req)) & 0xffffffff
        hdr = ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n" % FILE_SIZE).encode()
        wr(pkt(f, "s", "PA", f["ss"], f["cs"], hdr)); f["ss"] = (f["ss"] + len(hdr)) & 0xffffffff
        wr(pkt(f, "c", "A", f["cs"], f["ss"]))

    # Interleave body chunks round-robin so all files stay open at once.
    active = list(flows)
    while active:
        still = []
        for f in active:
            length = min(CHUNK, FILE_SIZE - f["sent"])
            wr(pkt(f, "s", "PA", f["ss"], f["cs"], body(f["id"], f["sent"], length)))
            f["ss"] = (f["ss"] + length) & 0xffffffff
            f["sent"] += length
            wr(pkt(f, "c", "A", f["cs"], f["ss"]))
            if f["sent"] < FILE_SIZE:
                still.append(f)
            else:
                wr(pkt(f, "s", "FA", f["ss"], f["cs"])); f["ss"] = (f["ss"] + 1) & 0xffffffff
                wr(pkt(f, "c", "A", f["cs"], f["ss"]))
                wr(pkt(f, "c", "FA", f["cs"], f["ss"])); f["cs"] = (f["cs"] + 1) & 0xffffffff
                wr(pkt(f, "s", "A", f["ss"], f["cs"]))
        active = still

    w.close()
    print("wrote %s: %d flows, %d bytes/file" % (a.output, a.n, FILE_SIZE))


if __name__ == "__main__":
    main()
