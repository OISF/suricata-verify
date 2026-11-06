#!/usr/bin/env python3
# Generates input.pcap: a single DCERPC/TCP flow with
#   BIND (call_id 1)    -> BINDNAK
#   BIND (call_id 2)    -> BINDACK, followed by AUTH3 (call_id 2) with no reply
#   REQUEST (call_id 3) -> FAULT
from scapy.all import IP, TCP, wrpcap
import struct

CLI, SRV = "10.0.0.1", "10.0.0.2"
CPORT, SPORT = 49152, 135


def hdr(ptype, frag_len, call_id):
    # rpc_vers 5.0, PFC_FIRST_FRAG | PFC_LAST_FRAG, little endian drep
    return struct.pack("<BBBBIHHI", 5, 0, ptype, 0x03, 0x10, frag_len, 0, call_id)


def bind(call_id):
    body = bytes.fromhex(
        "d016d016000000000100000000000100"
        "40fd2c346c3cce11a893 08002b2e9c6d00000000"
        "045d888aeb1cc9119fe808002b10486002000000".replace(" ", "")
    )
    return hdr(11, 16 + len(body), call_id) + body


def bindack(call_id):
    body = bytes.fromhex(
        "b810b8107dd800000d005c706970655c6c73617270630000"
        "01000000000000000000045d888aeb1cc9119fe808002b10486002000000"
    )
    return hdr(12, 16 + len(body), call_id) + body


def bindnak(call_id):
    # reject reason 4 (protocol version not supported), 1 supported version 5.0
    body = struct.pack("<HBBB", 4, 1, 5, 0) + b"\x00" * 3
    return hdr(13, 16 + len(body), call_id) + body


def auth3(call_id):
    body = b"\x00" * 4
    return hdr(16, 16 + len(body), call_id) + body


def request(call_id, opnum):
    stub = bytes(range(1, 9))
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    return hdr(0, 16 + len(body), call_id) + body


def fault(call_id):
    # status 5: nca_s_fault_access_denied
    body = struct.pack("<IHBBII", 32, 0, 0, 0, 5, 0)
    return hdr(3, 16 + len(body), call_id) + body


pkts = []
cseq, sseq = 1000, 5000


def c2s(flags, data=b""):
    global cseq
    pkts.append(IP(src=CLI, dst=SRV) / TCP(sport=CPORT, dport=SPORT, flags=flags, seq=cseq, ack=sseq) / data)
    cseq += len(data) + (1 if "S" in flags or "F" in flags else 0)


def s2c(flags, data=b""):
    global sseq
    pkts.append(IP(src=SRV, dst=CLI) / TCP(sport=SPORT, dport=CPORT, flags=flags, seq=sseq, ack=cseq) / data)
    sseq += len(data) + (1 if "S" in flags or "F" in flags else 0)


# handshake
pkts.append(IP(src=CLI, dst=SRV) / TCP(sport=CPORT, dport=SPORT, flags="S", seq=cseq - 1))
pkts.append(IP(src=SRV, dst=CLI) / TCP(sport=SPORT, dport=CPORT, flags="SA", seq=sseq - 1, ack=cseq))
c2s("A")

for data, to_server in [
    (bind(1), True),
    (bindnak(1), False),
    (bind(2), True),
    (bindack(2), False),
    (auth3(2), True),
    (request(3, 9), True),
    (fault(3), False),
]:
    if to_server:
        c2s("PA", data)
        s2c("A")
    else:
        s2c("PA", data)
        c2s("A")

c2s("FA")
s2c("FA")
c2s("A")

wrpcap("input.pcap", pkts)
