#!/usr/bin/env python
"""
Build a real multi-PDU fragmented DCE/RPC-over-TCP pcap for the
dcerpc.is_fragmented keyword test.

A single TCP connection carrying two calls, both client -> server:

  Call 1 (call_id 1): a REQUEST fragmented across TWO PDUs, each its own TCP
  segment, labelled with the connection-oriented fragmentation flags:
      PDU 1: PFC_FIRST_FRAG  (0x01)  -- first fragment
      PDU 2: PFC_LAST_FRAG   (0x02)  -- last fragment
  The RPC run-time reassembles these into a single request transaction; per
  C706 it is fragmented because no single PDU sets both FIRST and LAST.

  Call 2 (call_id 2): a single complete REQUEST PDU with both PFC_FIRST_FRAG and
  PFC_LAST_FRAG set (0x03) -- not fragmented.

So dcerpc.is_fragmented:yes matches call 1 and dcerpc.is_fragmented:no matches
call 2. A DCE/RPC connection whose first PDU is a request (05 00 00 ...) is
detected as DCERPC to_server, so no bind is required.

Connection-oriented request PDU layout (little-endian data representation):
  header (16): 05 00 | ptype(00) | pfc_flags | 10 00 00 00 | frag_length(2) |
               auth_length(2)=0 | call_id(4)
  body:        alloc_hint(4) | ctx_id(2) | opnum(2) | stub...
"""

import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_IP = "192.168.0.1"
SERVER_IP = "192.168.0.2"
CLIENT_PORT = 1025
SERVER_PORT = 135
CMAC = "00:00:00:00:00:01"
SMAC = "00:00:00:00:00:02"

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02


def co_request(pfc_flags, call_id, ctx_id, opnum, stub):
    body = struct.pack("<I", len(stub))      # alloc_hint
    body += struct.pack("<H", ctx_id)        # p_cont_id
    body += struct.pack("<H", opnum)         # opnum
    body += stub
    frag_length = 16 + len(body)
    hdr = bytes([0x05, 0x00, 0x00, pfc_flags, 0x10, 0x00, 0x00, 0x00])
    hdr += struct.pack("<H", frag_length)    # frag_length
    hdr += struct.pack("<H", 0)              # auth_length
    hdr += struct.pack("<I", call_id)        # call_id
    return hdr + body


# Call 1: request fragmented across two PDUs (first then last) -> one tx.
frag1 = co_request(PFC_FIRST_FRAG, 1, 0, 0, b"\xaa" * 24)
frag2 = co_request(PFC_LAST_FRAG, 1, 0, 0, b"\xbb" * 24)
# Call 2: single complete request (both first and last set).
whole = co_request(PFC_FIRST_FRAG | PFC_LAST_FRAG, 2, 0, 1, b"\xcc" * 24)


def c2s(**kw):
    return Ether(src=CMAC, dst=SMAC) / IP(src=CLIENT_IP, dst=SERVER_IP) \
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, **kw)


def s2c(**kw):
    return Ether(src=SMAC, dst=CMAC) / IP(src=SERVER_IP, dst=CLIENT_IP) \
        / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, **kw)


cseq = 1000
sseq = 5000
pkts = []

# 3-way handshake
pkts.append(c2s(flags="S", seq=cseq))
pkts.append(s2c(flags="SA", seq=sseq, ack=cseq + 1))
cseq += 1
sseq += 1
pkts.append(c2s(flags="A", seq=cseq, ack=sseq))

# client -> server data segments, each a full DCE/RPC PDU
for payload in (frag1, frag2, whole):
    pkts.append(c2s(flags="PA", seq=cseq, ack=sseq) / Raw(load=payload))
    cseq += len(payload)
    pkts.append(s2c(flags="A", seq=sseq, ack=cseq))

wrpcap("input.pcap", pkts)
