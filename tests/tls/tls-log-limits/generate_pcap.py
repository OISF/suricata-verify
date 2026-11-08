#!/usr/bin/env python3
"""Generate a TLS handshake with oversized handshake arrays.

The ClientHello carries 300 cipher suites and 300 extensions. The logger
caps both arrays at 256 entries and sets ciphers_truncated/exts_truncated.
A small server certificate keeps the transaction loggable.
"""
from scapy.all import Ether, IP, TCP, Raw, wrpcap

CN_OID = bytes([0x06, 0x03, 0x55, 0x04, 0x03])
RSA_OID = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])


def tlv(tag, content):
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    blen = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(blen)]) + blen + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def name(cn_value):
    return tlv(0x30, tlv(0x31, seq(CN_OID, tlv(0x0C, cn_value))))


SPKI = seq(seq(RSA_OID, bytes([0x05, 0x00])), tlv(0x03, bytes([0x00, 0xAA])))
VALIDITY = seq(tlv(0x17, b"250101000000Z"), tlv(0x17, b"250101000000Z"))
tbs = seq(
    tlv(0xA0, tlv(0x02, bytes([0x02]))),
    tlv(0x02, bytes([0x01])),
    seq(RSA_OID),
    name(b"x"),
    VALIDITY,
    name(bytes(500)),
    SPKI,
)
cert = seq(tbs, seq(RSA_OID), tlv(0x03, bytes([0x00, 0xAA])))


def hs(mtype, body):
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def record(payload):
    return bytes([22, 3, 3]) + len(payload).to_bytes(2, "big") + payload


N = 300
suites = b"".join((0x1300 + i).to_bytes(2, "big") for i in range(N))
exts = b"".join((0x1000 + i).to_bytes(2, "big") + b"\x00\x00" for i in range(N))
ch_body = (
    bytes([0x03, 0x03]) + bytes(32) + bytes([0x00])
    + len(suites).to_bytes(2, "big") + suites
    + bytes([0x01, 0x00])
    + len(exts).to_bytes(2, "big") + exts
)
client_hello = record(hs(1, ch_body))

rnd = bytes(32)
server_hello = record(hs(2, bytes([0x03, 0x03]) + rnd + bytes([0x00, 0x00, 0x2F, 0x00])))
cert_entry = len(cert).to_bytes(3, "big") + cert
cert_body = len(cert_entry).to_bytes(3, "big") + cert_entry
server = server_hello + record(hs(11, cert_body))

e1, e2 = "02:42:00:00:00:01", "02:42:00:00:00:02"


def pkt(src, dst, sport, dport, flags, seq, ack, load=b""):
    p = Ether(src=src, dst=dst) / IP(src="192.0.2.1" if src == e1 else "192.0.2.2",
                                     dst="192.0.2.2" if src == e1 else "192.0.2.1")
    p = p / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if load:
        p = p / Raw(load=load)
    return p


pkts = [
    pkt(e1, e2, 1234, 443, "S", 1000, 1000),
    pkt(e2, e1, 443, 1234, "SA", 2000, 1001),
    pkt(e1, e2, 1234, 443, "PA", 1001, 2001, client_hello),
    pkt(e2, e1, 443, 1234, "PA", 2001, 1001 + len(client_hello), server),
]
wrpcap("tls.pcap", pkts)
print("client_hello:", len(client_hello), "cert DER:", len(cert), "packets:", len(pkts))
