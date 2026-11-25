#!/usr/bin/env python
"""
Generate a DCE/RPC-over-TCP pcap where one request is split over more
fragments than a u16 fragment counter can hold.

  1. client -> server : BIND        pfc_flags 0x03  call id 1
  2. server -> client : BIND_ACK    pfc_flags 0x03  call id 1
  3. client -> server : REQUEST     pfc_flags 0x01  call id 2  stub "A"
  4. client -> server : REQUEST     pfc_flags 0x00  call id 2  stub "A"
     ... 65535 middle fragments in total ...
  5. client -> server : REQUEST     pfc_flags 0x02  call id 2  stub "A"

That is 65537 request fragments, one more than 65536. Each fragment carries
one byte of stub data, as a fragment without stub data is not counted. As
many whole fragments as fit are packed into each TCP segment to keep the pcap
small.
"""

import struct

from scapy.all import Ether, IP, TCP, Raw, PcapWriter

CLIENT_IP = "192.168.0.1"
SERVER_IP = "192.168.0.2"
CLIENT_PORT = 1025
SERVER_PORT = 135

PTYPE_REQUEST = 0x00
PTYPE_BIND = 0x0B
PTYPE_BIND_ACK = 0x0C

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02

IFACE_UUID = bytes.fromhex("4b324fc8167001d30012785a47bf6ee2")
XFER_UUID = bytes.fromhex("045d888aeb1cc9119fe808002b104860")

FRAGMENTS = 65537
SEGMENT_PAYLOAD_MAX = 1448


def co_header(ptype, pfc_flags, call_id, body):
    """Build a 16-byte connection-oriented DCE/RPC header plus body."""
    return (
        struct.pack(
            "<BBBB4sHHI",
            0x05,               # rpc_vers
            0x00,               # rpc_vers_minor
            ptype,
            pfc_flags,
            b"\x10\x00\x00\x00",  # packed_drep (little-endian)
            16 + len(body),     # frag_length
            0,                  # auth_length
            call_id,
        )
        + body
    )


def bind(call_id):
    body = struct.pack("<HHI", 5840, 5840, 0)      # max xmit/recv frag, assoc group
    body += struct.pack("<BBH", 1, 0, 0)           # num ctx items
    body += struct.pack("<HBB", 0, 1, 0)           # ctx id, num trans items
    body += IFACE_UUID + struct.pack("<HH", 1, 0)  # iface uuid + version
    body += XFER_UUID + struct.pack("<I", 2)       # transfer syntax + version
    return co_header(PTYPE_BIND, PFC_FIRST_FRAG | PFC_LAST_FRAG, call_id, body)


def bind_ack(call_id):
    sec_addr = b"\\PIPE\\ntsvcs\x00"
    body = struct.pack("<HHI", 5840, 5840, 0x1063)   # max xmit/recv frag, assoc group
    body += struct.pack("<H", len(sec_addr)) + sec_addr
    # sec addr is padded so that its length field plus itself is 4 byte aligned
    pad = (len(sec_addr) + 2) % 4
    if pad:
        body += b"\x00" * (4 - pad)
    body += struct.pack("<BBH", 1, 0, 0)             # num results + padding
    body += struct.pack("<HH", 0, 0)                 # ack result, ack reason
    body += XFER_UUID + struct.pack("<I", 2)         # transfer syntax + version
    return co_header(PTYPE_BIND_ACK, PFC_FIRST_FRAG | PFC_LAST_FRAG, call_id, body)


def request(pfc_flags, call_id, opnum, stub):
    # alloc_hint, context id, opnum, then stub data
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    return co_header(PTYPE_REQUEST, pfc_flags, call_id, body)


def request_fragments():
    for i in range(FRAGMENTS):
        if i == 0:
            flags = PFC_FIRST_FRAG
        elif i == FRAGMENTS - 1:
            flags = PFC_LAST_FRAG
        else:
            flags = 0x00
        yield request(flags, 2, 0x0B, b"A")


def segments(pdus):
    """Pack whole PDUs into segments of at most SEGMENT_PAYLOAD_MAX bytes."""
    seg = b""
    for pdu in pdus:
        if seg and len(seg) + len(pdu) > SEGMENT_PAYLOAD_MAX:
            yield seg
            seg = b""
        seg += pdu
    if seg:
        yield seg


def write_pcap(path):
    c_eth = {"dst": "00:00:00:00:00:02", "src": "00:00:00:00:00:01"}
    s_eth = {"dst": "00:00:00:00:00:01", "src": "00:00:00:00:00:02"}

    def to_server(**kw):
        return (Ether(**c_eth) / IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, **kw))

    def to_client(**kw):
        return (Ether(**s_eth) / IP(src=SERVER_IP, dst=CLIENT_IP)
                / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, **kw))

    out = PcapWriter(path, linktype=1, sync=False)
    cseq, sseq = 1000, 2000
    out.write(to_server(flags="S", seq=cseq))
    out.write(to_client(flags="SA", seq=sseq, ack=cseq + 1))
    out.write(to_server(flags="A", seq=cseq + 1, ack=sseq + 1))
    cseq += 1
    sseq += 1

    flow = [("ts", bind(1)), ("tc", bind_ack(1))]
    flow += [("ts", seg) for seg in segments(request_fragments())]

    # each payload is sent in its own segment and acked by the peer
    for direction, payload in flow:
        if direction == "ts":
            out.write(to_server(flags="PA", seq=cseq, ack=sseq) / Raw(load=payload))
            cseq += len(payload)
            out.write(to_client(flags="A", seq=sseq, ack=cseq))
        else:
            out.write(to_client(flags="PA", seq=sseq, ack=cseq) / Raw(load=payload))
            sseq += len(payload)
            out.write(to_server(flags="A", seq=cseq, ack=sseq))

    # close the connection so the tx is logged
    out.write(to_server(flags="FA", seq=cseq, ack=sseq))
    out.write(to_client(flags="FA", seq=sseq, ack=cseq + 1))
    out.write(to_server(flags="A", seq=cseq + 1, ack=sseq + 1))
    out.close()


write_pcap("input.pcap")
