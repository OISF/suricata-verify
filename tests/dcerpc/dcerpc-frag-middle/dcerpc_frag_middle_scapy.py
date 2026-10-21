#!/usr/bin/env python
"""
Generate a DCE/RPC-over-TCP pcap where the request and the response are each
split over three fragments, for the middle fragment reassembly test.

C706 labels a fragmented PDU with PFC_FIRST_FRAG (0x01) on the first fragment
and PFC_LAST_FRAG (0x02) on the last, so a middle fragment carries neither and
its fragment bits are 0x00. All fragments share a call id.

  1. client -> server : BIND        pfc_flags 0x03
  2. server -> client : BIND_ACK    pfc_flags 0x03
  3. client -> server : REQUEST     pfc_flags 0x01  stub "AAAAAAAA"
  4. client -> server : REQUEST     pfc_flags 0x00  stub "BBBBBBBB"
  5. client -> server : REQUEST     pfc_flags 0x02  stub "CCCCCCCC"
  6. server -> client : RESPONSE    pfc_flags 0x01  stub "aaaaaaaa"
  7. server -> client : RESPONSE    pfc_flags 0x00  stub "bbbbbbbb"
  8. server -> client : RESPONSE    pfc_flags 0x02  stub "cccccccc"
"""

import struct

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT_IP = "192.168.0.1"
SERVER_IP = "192.168.0.2"
CLIENT_PORT = 1025
SERVER_PORT = 135

PTYPE_REQUEST = 0x00
PTYPE_RESPONSE = 0x02
PTYPE_BIND = 0x0B
PTYPE_BIND_ACK = 0x0C

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02
PFC_OBJECT_UUID = 0x80

RPC_C_AUTHN_WINNT = 10
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5

IFACE_UUID = bytes.fromhex("4b324fc8167001d30012785a47bf6ee2")
XFER_UUID = bytes.fromhex("045d888aeb1cc9119fe808002b104860")


def co_header(ptype, pfc_flags, call_id, body, auth=b""):
    """Build a 16-byte connection-oriented DCE/RPC header plus body. If auth
    is given, a sec_trailer and the auth value follow the body."""
    trailer = b""
    if auth:
        # auth type, auth level, pad length, reserved, context id
        trailer = struct.pack("<BBBBI", RPC_C_AUTHN_WINNT,
                              RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, 0, 0, 0) + auth
    return (
        struct.pack(
            "<BBBB4sHHI",
            0x05,               # rpc_vers
            0x00,               # rpc_vers_minor
            ptype,
            pfc_flags,
            b"\x10\x00\x00\x00",  # packed_drep (little-endian)
            16 + len(body) + len(trailer),  # frag_length
            len(auth),          # auth_length
            call_id,
        )
        + body
        + trailer
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


def request(pfc_flags, call_id, opnum, stub, auth=b"", object_uuid=None):
    # alloc_hint, context id, opnum, optional object uuid, then stub data
    body = struct.pack("<IHH", len(stub), 0, opnum)
    if object_uuid is not None:
        pfc_flags |= PFC_OBJECT_UUID
        body += object_uuid
    body += stub
    return co_header(PTYPE_REQUEST, pfc_flags, call_id, body, auth)


def response(pfc_flags, call_id, stub):
    # alloc_hint, context id, cancel count, reserved, then stub data
    body = struct.pack("<IHBB", len(stub), 0, 0, 0) + stub
    return co_header(PTYPE_RESPONSE, pfc_flags, call_id, body)


def create_pcap(flow):
    """flow is a list of ("ts" | "tc", payload) in wire order. Each payload
    is sent in its own segment and acked by the peer."""
    c_eth = {"dst": "00:00:00:00:00:02", "src": "00:00:00:00:00:01"}
    s_eth = {"dst": "00:00:00:00:00:01", "src": "00:00:00:00:00:02"}

    def to_server(**kw):
        return (Ether(**c_eth) / IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, **kw))

    def to_client(**kw):
        return (Ether(**s_eth) / IP(src=SERVER_IP, dst=CLIENT_IP)
                / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, **kw))

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


flow = [
    ("ts", bind(1)),
    ("tc", bind_ack(1)),
    ("ts", request(PFC_FIRST_FRAG, 2, 0x0B, b"A" * 8)),
    ("ts", request(0x00, 2, 0x0B, b"B" * 8)),
    ("ts", request(PFC_LAST_FRAG, 2, 0x0B, b"C" * 8)),
    ("tc", response(PFC_FIRST_FRAG, 2, b"a" * 8)),
    ("tc", response(0x00, 2, b"b" * 8)),
    ("tc", response(PFC_LAST_FRAG, 2, b"c" * 8)),
]
wrpcap("input.pcap", create_pcap(flow))
