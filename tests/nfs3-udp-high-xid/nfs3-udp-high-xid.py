#!/usr/bin/env python3
"""Generate the nfs3-udp-high-xid fixture.

Unmarked v3/UDP transfer whose xids carry the top bit set. The
write/read xids (0x80000030/31) imply plausible marker claims (48/49)
that do not end at the datagram boundary; the NULL-exchange xid
(0x80000003) implies a claim below the 24-byte minimum. The header
sniff must fall back to the unmarked layout in all cases and parse
exactly as unmarked. Same transfer shape as
nfs3-udp-marked-transfer: detection + a 4096B FILE_SYNC write + a
4096B read reply assembling the file.
"""
import os
from scapy.all import IP, UDP, Raw, wrpcap

CLIENT = "192.168.1.6"
SERVER = "192.168.1.2"
CPORT = 939
SPORT = 2049


def be32(v):
    return v.to_bytes(4, "big")


def be64(v):
    return v.to_bytes(8, "big")


def fh(fill):
    data = b"\x01\x00\x00\x00" + bytes([fill]) * 28
    return be32(len(data)) + data


def cred():
    # auth_none: the other NFS fixtures use it; keeps the calls short
    return be32(0) + be32(0)


def call(xid, proc, prog_data):
    body = (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(3) + be32(proc)
        + cred() + be32(0) + be32(0) + prog_data
    )
    return body


def reply(xid, prog_data):
    # xid + msgtype + null verf + reply_state + accept_state
    return be32(xid) + be32(1) + be32(0) + be32(0) + be32(0) + be32(0) + prog_data


DATA = b"A" * 4096

# xid 0x80000003: implied claim 3, below the 24-byte minimum (both
# directions of the NULL exchange)
null_call = call(0x8000_0003, 0, b"")
null_reply = reply(0x8000_0003, be32(0))

# xid 0x80000030: implied claim 48, plausible but the datagrams do not
# end at the claimed boundary -> unmarked in both directions
write_req = call(0x8000_0030, 7, fh(0x10) + be64(0) + be32(4096)
                 + be32(2) + be32(4096) + DATA)
# the write reply carries only the status
write_rep = reply(0x8000_0030, be32(0))

# xid 0x80000031: implied claim 49 on a small request datagram
read_req = call(0x8000_0031, 6, fh(0x10) + be64(0) + be32(4096))
# read reply in the accepted parser shape (attr_follows + count + eof +
# datalen + data): tshark's strict wcc_data decoder flags it, as it
# does the mainline nfs3-read-attr-follows-0 fixture
read_rep = reply(0x8000_0031, be32(0) + be32(0) + be32(4096)
                 + be32(1) + be32(4096) + DATA)


pkts = [
    IP(src=CLIENT, dst=SERVER) / UDP(sport=CPORT, dport=SPORT) / Raw(load=write_req),
    IP(src=SERVER, dst=CLIENT) / UDP(sport=SPORT, dport=CPORT) / Raw(load=write_rep),
    IP(src=CLIENT, dst=SERVER) / UDP(sport=CPORT, dport=SPORT) / Raw(load=null_call),
    IP(src=SERVER, dst=CLIENT) / UDP(sport=SPORT, dport=CPORT) / Raw(load=null_reply),
    IP(src=CLIENT, dst=SERVER) / UDP(sport=CPORT, dport=SPORT) / Raw(load=read_req),
    IP(src=SERVER, dst=CLIENT) / UDP(sport=SPORT, dport=CPORT) / Raw(load=read_rep),
]

# fixed stamps: the committed pcap must be byte-stable across regenerations
for _i, _p in enumerate(pkts):
    _p.time = 1735689600.0 + _i * 0.01

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
wrpcap(out, pkts)
for name, b in [("write_req", write_req), ("write_rep", write_rep),
                ("null_call", null_call), ("null_reply", null_reply),
                ("read_req", read_req), ("read_rep", read_rep)]:
    print(name, len(b), "claim", int.from_bytes(b[:4], "big") & 0x7FFF)
