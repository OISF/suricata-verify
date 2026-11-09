#!/usr/bin/env python3
"""Generate test.pcap for lua-dnp3-retain-points.

Two TCP connections on the same 5-tuple, separated by a time gap larger than
the default established-flow timeout (300s):

  * Phase 1: handshake, one DNP3 request transaction carrying a 33-point
    group-1 variation-1 object (above the 32-point eager threshold, so the
    lua `points` value is the lazy userdata), then a plain ACK.
  * Phase 2: a fresh SYN (new ISN) on the same 5-tuple starts a new
    connection and a new DNP3 state, carrying a second identical request.

Because the gap exceeds the established-flow timeout, the first connection's
flow is freed before the second connection's SYN arrives, so phase 2 runs on
a new DNP3 state (a new generation) while staying on the same worker (same
5-tuple). When the second connection's detection callback runs, the lifetime
check in the retained points userdata (which references the first
connection's freed transaction) fails and the retained value reads as nil,
while the second connection's own points value is still alive.

Pre-fix, the retained userdata still followed its transaction-owned pointers
after the free (use-after-free / stale heap read, observable under ASan).
The fixed code returns nil, which the rule turns into an alert.

Each DNP3 frame is a complete transaction: transport th = 0xC0 | seq
(FIR+FIN) so the transaction is final and decoded, following the proven
dnp3-flood/gen_pcap.py structure.
"""

from scapy.all import IP, TCP, Raw, wrpcap

OUTPUT = "test.pcap"

SRC_IP = "192.168.1.100"
DST_IP = "192.168.1.200"
SRC_PORT = 10000
DST_PORT = 20000

# DNP3 link-layer addresses
DNP3_SRC = 3
DNP3_DST = 2

# Time gap between the two connections (seconds), in packet timestamps.
# Larger than the default established-flow timeout (300s) so the first
# connection's flow (and its DNP3 state) is freed before the second
# connection's SYN, guaranteeing a new DNP3 state (and a new generation).
GAP = 400.0


def dnp3_crc(data):
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return ((~crc) & 0xFFFF).to_bytes(2, "little")


def object33():
    """A 33-point group-1 variation-1 (binary) object.

    Object header (group, variation, qualifier) with qualifier range code 0
    (1-octet start/stop indexes), start=1 stop=33 -> count 33. G1V1 packs
    count bits into count/8+1 bytes; prefix code 0 -> no prefix octets.
    """
    group = 0x01
    variation = 0x01
    qualifier = 0x00
    start = 0x01
    stop = 0x21  # 33 -> count = 33
    data = bytes([0x01, 0x02, 0x04, 0x08, 0x10])  # count/8+1 = 5 bytes
    return bytes([group, variation, qualifier, start, stop]) + data


def build_frame(transport_seq):
    # Transport header: FIN=1, FIR=1, 6-bit sequence -> complete transaction.
    th = 0xC0 | (transport_seq & 0x3F)
    # Application header: control (FIR+FIN, 4-bit seq 0) + function code 2
    # (Write), matching the test rule's dnp3_func:2.
    app_ctrl = 0xC0
    funct = 0x02
    user_data = bytes([th, app_ctrl, funct]) + object33()

    # Chunk the user data with 16-byte CRCs.
    chunks = []
    for i in range(0, len(user_data), 16):
        chunk = user_data[i:i + 16]
        chunks.append(chunk + dnp3_crc(chunk))
    payload_with_crcs = b"".join(chunks)

    # Link header: length = 5 (ctrl + dst + src) + uncompressed user data.
    length = 5 + len(user_data)
    ctrl = 0xC4  # DIR=1, PRM=1 (request, master -> outstation)
    dst = DNP3_DST.to_bytes(2, "little")
    src = DNP3_SRC.to_bytes(2, "little")
    header_block = bytes([0x05, 0x64, length, ctrl]) + dst + src
    header_crc = dnp3_crc(header_block)
    return header_block + header_crc + payload_with_crcs


def connection(pkts, client_isn, server_isn):
    """Append a handshake, one DNP3 request, and an ACK starting at t0."""
    cseq, sseq = client_isn, server_isn

    pkts.append(IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT,
                flags="S", seq=cseq))
    cseq += 1
    pkts.append(IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT,
                flags="SA", seq=sseq, ack=cseq))
    sseq += 1
    pkts.append(IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT,
                flags="A", seq=cseq, ack=sseq))

    frame = build_frame(0)
    pkts.append(IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT,
                flags="PA", seq=cseq, ack=sseq) / Raw(load=frame))
    cseq += len(frame)

    pkts.append(IP(src=DST_IP, dst=SRC_IP) / TCP(sport=DST_PORT, dport=SRC_PORT,
                flags="A", seq=sseq, ack=cseq))


def main():
    pkts = []

    # Phase 1 (t=0): first connection.
    t0 = 0.0
    connection(pkts, client_isn=1000, server_isn=5000)

    # Phase 2 (t=GAP): fresh connection on the same 5-tuple (new ISNs).
    connection(pkts, client_isn=9000, server_isn=19000)

    base = 1700000000.0
    # Each connection() appends 5 packets; assign increasing timestamps so
    # the GAP between the phases is real (phase 1 at t=0.., phase 2 at GAP..).
    half = len(pkts) // 2
    for i, pkt in enumerate(pkts):
        if i < half:
            pkt.time = base + i * 0.001
        else:
            pkt.time = base + GAP + (i - half) * 0.001

    wrpcap(OUTPUT, pkts)
    print(f"Created {OUTPUT} with {len(pkts)} packets")


if __name__ == "__main__":
    main()
