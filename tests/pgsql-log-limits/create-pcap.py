#!/usr/bin/env python3
"""Generate pgsql-log-limits.pcap: oversized pgsql fields and message lists.

One PostgreSQL session:
  1. StartupMessage with 1100-byte user and application_name values
  2. AuthenticationOk, 300 ParameterStatus messages, ReadyForQuery
                                                -> response list cut
  3. SimpleQuery with a 1200-byte query, CommandComplete, ReadyForQuery
                                                -> in-value marker

Regenerate with: python3 create-pcap.py
"""

import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 5000
SERVER_PORT = 5432


def msg(t: bytes, body: bytes) -> bytes:
    return t + struct.pack(">I", len(body) + 4) + body


def ps(name: bytes, value: bytes) -> bytes:
    return msg(b"S", name + b"\0" + value + b"\0")


startup_body = (
    struct.pack(">I", 196608)  # protocol 3.0
    + b"user\0"
    + b"U" * 1100
    + b"\0"
    + b"application_name\0"
    + b"A" * 1100
    + b"\0"
    + b"\0"
)
startup = struct.pack(">I", len(startup_body) + 4) + startup_body
auth_ok = msg(b"R", struct.pack(">I", 0))
params = b"".join(ps(b"server_version", b"16.0") for _ in range(300))
ready = msg(b"Z", b"I")
query = msg(b"Q", b"Q" * 1200 + b"\0")
complete = msg(b"C", b"SELECT 1\0")

pkts = []
c_seq, s_seq = 1000, 2000
pkts.append(
    Ether(src=SRC_MAC, dst=DST_MAC)
    / IP(src=CLIENT_IP, dst=SERVER_IP)
    / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=c_seq, window=65535)
)
pkts.append(
    Ether(src=DST_MAC, dst=SRC_MAC)
    / IP(src=SERVER_IP, dst=CLIENT_IP)
    / TCP(
        sport=SERVER_PORT,
        dport=CLIENT_PORT,
        flags="SA",
        seq=s_seq,
        ack=c_seq + 1,
        window=65535,
    )
)
pkts.append(
    Ether(src=SRC_MAC, dst=DST_MAC)
    / IP(src=CLIENT_IP, dst=SERVER_IP)
    / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=c_seq + 1, ack=s_seq + 1)
)
c_seq += 1
s_seq += 1

for client_data, server_data in (
    (startup, auth_ok + params + ready),
    (query, complete + ready),
):
    pkts.append(
        Ether(src=SRC_MAC, dst=DST_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="PA",
            seq=c_seq,
            ack=s_seq,
        )
        / Raw(load=client_data)
    )
    c_seq += len(client_data)
    pkts.append(
        Ether(src=DST_MAC, dst=SRC_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags="PA",
            seq=s_seq,
            ack=c_seq,
        )
        / Raw(load=server_data)
    )
    s_seq += len(server_data)

wrpcap("pgsql-log-limits.pcap", pkts)
total = sum(len(p[Raw].load) for p in pkts if Raw in p)
print(f"wrote pgsql-log-limits.pcap: {len(pkts)} frames, {total} tcp-payload bytes")
