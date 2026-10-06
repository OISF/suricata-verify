#!/usr/bin/env python3
"""
Generate a PCAP with several DCERPC over TCP connections exercising the
PFC_FIRST_FRAG handling of the dcerpc.iface keyword and its any_frag option.

Each connection binds to a test interface and then issues one request /
response pair. The connections differ in the pfc_flags of the BIND, REQUEST
and RESPONSE PDUs. See README.md for details.

Usage: ./generate-pcap.py input.pcap
"""

import struct
import sys
import uuid

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SERVER_PORT = 135

# Test interface UUID (not a real interface), version 3.0
IFACE_UUID = uuid.UUID("12345678-1234-abcd-ef00-01234567cffb")
# NDR transfer syntax, version 2
NDR_UUID = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")

PTYPE_REQUEST = 0
PTYPE_RESPONSE = 2
PTYPE_BIND = 11
PTYPE_BIND_ACK = 12

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02


def hdr(ptype, pfc_flags, call_id, body):
    """Connection-oriented DCERPC header, version 5.0, little endian DREP."""
    frag_length = 16 + len(body)
    return (
        struct.pack("<BBBB", 5, 0, ptype, pfc_flags)
        + bytes([0x10, 0x00, 0x00, 0x00])
        + struct.pack("<HHI", frag_length, 0, call_id)
        + body
    )


def bind(pfc_flags, call_id=1):
    ctx_item = (
        struct.pack("<HBB", 0, 1, 0)
        + IFACE_UUID.bytes_le
        + struct.pack("<HH", 3, 0)
        + NDR_UUID.bytes_le
        + struct.pack("<I", 2)
    )
    body = struct.pack("<HHIB", 5840, 5840, 0, 1) + b"\x00" * 3 + ctx_item
    return hdr(PTYPE_BIND, pfc_flags, call_id, body)


def bind_ack(pfc_flags, call_id=1):
    sec_addr = b"135\x00"
    body = struct.pack("<HHIH", 5840, 5840, 0x1234, len(sec_addr)) + sec_addr
    # Pad to 4 byte alignment (2 byte length + address).
    pad = (4 - (2 + len(sec_addr)) % 4) % 4
    body += b"\x00" * pad
    body += struct.pack("<B", 1) + b"\x00" * 3
    body += struct.pack("<HH", 0, 0) + NDR_UUID.bytes_le + struct.pack("<I", 2)
    return hdr(PTYPE_BIND_ACK, pfc_flags, call_id, body)


def request(pfc_flags, stub, call_id=2, ctx_id=0, opnum=3):
    body = struct.pack("<IHH", len(stub), ctx_id, opnum) + stub
    return hdr(PTYPE_REQUEST, pfc_flags, call_id, body)


def response(pfc_flags, stub, call_id=2, ctx_id=0):
    body = struct.pack("<IHBB", len(stub), ctx_id, 0, 0) + stub
    return hdr(PTYPE_RESPONSE, pfc_flags, call_id, body)


class Conn:
    """Minimal TCP connection builder with correct seq/ack tracking."""

    def __init__(self, sport):
        self.sport = sport
        self.cseq = 1000
        self.sseq = 5000
        self.pkts = []
        self.pkts.append(self._pkt(True, "S"))
        self.cseq += 1
        self.pkts.append(self._pkt(False, "SA"))
        self.sseq += 1
        self.pkts.append(self._pkt(True, "A"))

    def _pkt(self, to_server, flags, payload=b""):
        if to_server:
            p = (
                Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
                / IP(src=CLIENT, dst=SERVER)
                / TCP(
                    sport=self.sport,
                    dport=SERVER_PORT,
                    flags=flags,
                    seq=self.cseq,
                    ack=self.sseq,
                )
            )
        else:
            p = (
                Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
                / IP(src=SERVER, dst=CLIENT)
                / TCP(
                    sport=SERVER_PORT,
                    dport=self.sport,
                    flags=flags,
                    seq=self.sseq,
                    ack=self.cseq,
                )
            )
        if payload:
            p = p / Raw(load=payload)
        return p

    def to_server(self, payload):
        self.pkts.append(self._pkt(True, "PA", payload))
        self.cseq += len(payload)
        self.pkts.append(self._pkt(False, "A"))

    def to_client(self, payload):
        self.pkts.append(self._pkt(False, "PA", payload))
        self.sseq += len(payload)
        self.pkts.append(self._pkt(True, "A"))

    def close(self):
        self.pkts.append(self._pkt(True, "FA"))
        self.cseq += 1
        self.pkts.append(self._pkt(False, "FA"))
        self.sseq += 1
        self.pkts.append(self._pkt(True, "A"))


STUB = bytes(range(0x41, 0x41 + 24))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    pkts = []

    # 40001: BIND with pfc_flags 0 (no FIRST/LAST frag flags), request and
    # response are normal first+last fragments.
    c = Conn(40001)
    c.to_server(bind(0x00))
    c.to_client(bind_ack(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_server(request(PFC_FIRST_FRAG | PFC_LAST_FRAG, STUB))
    c.to_client(response(PFC_FIRST_FRAG | PFC_LAST_FRAG, STUB))
    c.close()
    pkts += c.pkts

    # 40002: Request fragmented in two PDUs: first frag, then last frag.
    c = Conn(40002)
    c.to_server(bind(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_client(bind_ack(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_server(request(PFC_FIRST_FRAG, STUB[:12]))
    c.to_server(request(PFC_LAST_FRAG, STUB[12:]))
    c.to_client(response(PFC_FIRST_FRAG | PFC_LAST_FRAG, STUB))
    c.close()
    pkts += c.pkts

    # 40003: Request with pfc_flags 0, i.e. neither FIRST nor LAST frag
    # flag set. In Snort terms this is a middle fragment.
    c = Conn(40003)
    c.to_server(bind(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_client(bind_ack(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_server(request(0x00, STUB))
    c.to_client(response(PFC_FIRST_FRAG | PFC_LAST_FRAG, STUB))
    c.close()
    pkts += c.pkts

    # 40004: Request with only the LAST frag flag set (first fragment
    # never seen).
    c = Conn(40004)
    c.to_server(bind(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_client(bind_ack(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_server(request(PFC_LAST_FRAG, STUB))
    c.to_client(response(PFC_FIRST_FRAG | PFC_LAST_FRAG, STUB))
    c.close()
    pkts += c.pkts

    # 40005: Normal request, response with only the LAST frag flag set.
    c = Conn(40005)
    c.to_server(bind(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_client(bind_ack(PFC_FIRST_FRAG | PFC_LAST_FRAG))
    c.to_server(request(PFC_FIRST_FRAG | PFC_LAST_FRAG, STUB))
    c.to_client(response(PFC_LAST_FRAG, STUB))
    c.close()
    pkts += c.pkts

    # Give the packets increasing timestamps.
    t = 1700000000.0
    for p in pkts:
        p.time = t
        t += 0.001

    wrpcap(out, pkts)
    print("wrote %d packets to %s" % (len(pkts), out))


if __name__ == "__main__":
    main()
