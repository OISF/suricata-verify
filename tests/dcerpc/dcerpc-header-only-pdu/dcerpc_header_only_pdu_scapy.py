#!/usr/bin/env python
"""
Generate a DCE/RPC-over-TCP pcap with header-only PDUs: REQUEST and RESPONSE
PDUs whose frag_length is 16, so they consist of the common header only and
have no PDU body at all.

There are two connections, so that each case is tested on its own.

Connection 1 (client port 1025), every PDU in its own segment:
  1. client -> server : BIND        call id 1
  2. server -> client : BIND_ACK    call id 1
  3. client -> server : REQUEST     call id 3  header only
  4. server -> client : RESPONSE    call id 3  header only
  5. client -> server : REQUEST     call id 2  stub "AAAAAAAA"
  6. server -> client : RESPONSE    call id 2  stub "aaaaaaaa"

Connection 2 (client port 1026), each header-only PDU shares a segment with
the PDU that follows it:
  1. client -> server : BIND        call id 1
  2. server -> client : BIND_ACK    call id 1
  3. client -> server : REQUEST     call id 3  header only
     + REQUEST                        call id 2  stub "AAAAAAAA"  (same segment)
  4. server -> client : RESPONSE    call id 3  header only
     + RESPONSE                       call id 2  stub "aaaaaaaa"  (same segment)

All PDUs have both PFC_FIRST_FRAG and PFC_LAST_FRAG set.
"""

import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_IP = "192.168.0.1"
SERVER_IP = "192.168.0.2"
SERVER_PORT = 135

PTYPE_REQUEST = 0x00
PTYPE_RESPONSE = 0x02
PTYPE_BIND = 0x0B
PTYPE_BIND_ACK = 0x0C

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02
PFC_FIRST_LAST = PFC_FIRST_FRAG | PFC_LAST_FRAG

IFACE_UUID = bytes.fromhex("4b324fc8167001d30012785a47bf6ee2")
XFER_UUID = bytes.fromhex("045d888aeb1cc9119fe808002b104860")


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
    return co_header(PTYPE_BIND, PFC_FIRST_LAST, call_id, body)


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
    return co_header(PTYPE_BIND_ACK, PFC_FIRST_LAST, call_id, body)


def request(call_id, opnum, stub):
    # alloc_hint, context id, opnum, then stub data
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    return co_header(PTYPE_REQUEST, PFC_FIRST_LAST, call_id, body)


def response(call_id, stub):
    # alloc_hint, context id, cancel count, reserved, then stub data
    body = struct.pack("<IHBB", len(stub), 0, 0, 0) + stub
    return co_header(PTYPE_RESPONSE, PFC_FIRST_LAST, call_id, body)


def header_only(ptype, call_id):
    return co_header(ptype, PFC_FIRST_LAST, call_id, b"")


def create_flow(client_port, flow):
    """flow is a list of ("ts" | "tc", payload) in wire order. Each payload
    is sent in its own segment and acked by the peer."""
    c_eth = {"dst": "00:00:00:00:00:02", "src": "00:00:00:00:00:01"}
    s_eth = {"dst": "00:00:00:00:00:01", "src": "00:00:00:00:00:02"}

    def to_server(**kw):
        return (Ether(**c_eth) / IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(sport=client_port, dport=SERVER_PORT, **kw))

    def to_client(**kw):
        return (Ether(**s_eth) / IP(src=SERVER_IP, dst=CLIENT_IP)
                / TCP(sport=SERVER_PORT, dport=client_port, **kw))

    cseq, sseq = 1000, 2000
    pkts = [
        to_server(flags="S", seq=cseq),
        to_client(flags="SA", seq=sseq, ack=cseq + 1),
        to_server(flags="A", seq=cseq + 1, ack=sseq + 1),
    ]
    cseq += 1
    sseq += 1

    for direction, payload in flow:
        if direction == "ts":
            pkts.append(to_server(flags="PA", seq=cseq, ack=sseq) / Raw(load=payload))
            cseq += len(payload)
            pkts.append(to_client(flags="A", seq=sseq, ack=cseq))
        else:
            pkts.append(to_client(flags="PA", seq=sseq, ack=cseq) / Raw(load=payload))
            sseq += len(payload)
            pkts.append(to_server(flags="A", seq=cseq, ack=sseq))

    # close the connection so every tx is logged
    pkts.append(to_server(flags="FA", seq=cseq, ack=sseq))
    pkts.append(to_client(flags="FA", seq=sseq, ack=cseq + 1))
    pkts.append(to_server(flags="A", seq=cseq + 1, ack=sseq + 1))
    return pkts


separate = [
    ("ts", bind(1)),
    ("tc", bind_ack(1)),
    ("ts", header_only(PTYPE_REQUEST, 3)),
    ("tc", header_only(PTYPE_RESPONSE, 3)),
    ("ts", request(2, 0x0B, b"A" * 8)),
    ("tc", response(2, b"a" * 8)),
]

coalesced = [
    ("ts", bind(1)),
    ("tc", bind_ack(1)),
    ("ts", header_only(PTYPE_REQUEST, 3) + request(2, 0x0B, b"A" * 8)),
    ("tc", header_only(PTYPE_RESPONSE, 3) + response(2, b"a" * 8)),
]

wrpcap("input.pcap", create_flow(1025, separate) + create_flow(1026, coalesced))
