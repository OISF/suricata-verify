#!/usr/bin/env python3
#
# Regenerate input.pcap for the tls-too-many-sans test.
#
# Builds a TLS 1.2 server flight whose leaf certificate carries 65537
# subjectAltName entries, i.e. one more than fits in a u16.  See README.md for
# what the test asserts.
#
# Requires scapy.  Usage:  python3 generate-pcap.py

from scapy.all import Ether, IP, TCP, Raw, wrpcap

# ---------------------------------------------------------------- DER helpers

SEQUENCE = 0x30
SET = 0x31
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
PRINTABLE_STRING = 0x13
UTC_TIME = 0x17
CTX_0 = 0xA0  # [0] EXPLICIT
CTX_3 = 0xA3  # [3] EXPLICIT
DNS_NAME = 0x82  # GeneralName [2] IMPLICIT IA5String


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append((p & 0x7F) | 0x80)
            p >>= 7
        out.extend(reversed(chunk))
    return tlv(OID, bytes(out))


OID_SHA256_RSA = oid("1.2.840.113549.1.1.11")
OID_RSA = oid("1.2.840.113549.1.1.1")
OID_CN = oid("2.5.4.3")
OID_SAN = oid("2.5.29.17")


def algid(alg_oid):
    return tlv(SEQUENCE, alg_oid + tlv(NULL, b""))


def name(cn):
    """RDNSequence with a single commonName."""
    atv = tlv(SEQUENCE, OID_CN + tlv(PRINTABLE_STRING, cn))
    return tlv(SEQUENCE, tlv(SET, atv))


# ------------------------------------------------------------------ SAN list
#
# 65537 entries total -- one past u16::MAX.
#
#   index 0            "a"             decoy, the only entry a truncating
#                                      (pre-fix) cast would ever expose
#   index 1            "evil.example"  the detection target: invisible if the
#                                      count truncates to 1, visible once the
#                                      count saturates to 65535
#   index 2..65536     "b"             1-byte filler to push the count over
#                                      u16::MAX without bloating the pcap
#
SAN_TOTAL = 65537
sans = [b"a", b"evil.example"] + [b"b"] * (SAN_TOTAL - 2)
assert len(sans) == SAN_TOTAL

general_names = tlv(SEQUENCE, b"".join(tlv(DNS_NAME, s) for s in sans))
san_extension = tlv(SEQUENCE, OID_SAN + tlv(OCTET_STRING, general_names))
extensions = tlv(CTX_3, tlv(SEQUENCE, san_extension))

# ---------------------------------------------------------------- certificate

version = tlv(CTX_0, tlv(INTEGER, b"\x02"))  # v3
serial = tlv(INTEGER, b"\x01")
validity = tlv(UTC_TIME, b"200101000000Z") + tlv(UTC_TIME, b"350101000000Z")
# Syntactically well-formed RSA key; never verified, Suricata only parses DER.
rsa_key = tlv(SEQUENCE, tlv(INTEGER, b"\x00" + b"\xc1" * 127) + tlv(INTEGER, b"\x01\x00\x01"))
spki = tlv(SEQUENCE, algid(OID_RSA) + tlv(BIT_STRING, b"\x00" + rsa_key))

tbs = tlv(
    SEQUENCE,
    version
    + serial
    + algid(OID_SHA256_RSA)
    + name(b"too-many-sans")
    + tlv(SEQUENCE, validity)
    + name(b"too-many-sans")
    + spki
    + extensions,
)
cert = tlv(SEQUENCE, tbs + algid(OID_SHA256_RSA) + tlv(BIT_STRING, b"\x00" + b"\xaa" * 128))

# ------------------------------------------------------------ TLS handshake

def u24(n):
    return n.to_bytes(3, "big")


def hs(msg_type, body):
    return bytes([msg_type]) + u24(len(body)) + body


client_hello = hs(
    0x01,
    b"\x03\x03"
    + bytes(range(32))
    + b"\x00"  # no session id
    + b"\x00\x02\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
    + b"\x01\x00"  # null compression
    + b"\x00\x00",  # no extensions
)
server_hello = hs(
    0x02,
    b"\x03\x03"
    + bytes(range(32, 64))
    + b"\x00"
    + b"\x00\x2f"
    + b"\x00"
    + b"\x00\x00",
)
certificate = hs(0x0B, u24(len(cert) + 3) + u24(len(cert)) + cert)
server_hello_done = hs(0x0E, b"")


def records(payload, version=b"\x03\x03"):
    """Split a handshake message into <=16384-byte TLS records."""
    out = b""
    for i in range(0, len(payload), 16384):
        chunk = payload[i : i + 16384]
        out += b"\x16" + version + len(chunk).to_bytes(2, "big") + chunk
    return out


to_server = records(client_hello, b"\x03\x01")
to_client = records(server_hello) + records(certificate) + records(server_hello_done)

# ------------------------------------------------------------------- the pcap

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
SPORT, DPORT = 40000, 443
MSS = 1460
# The server flight is ~200 KB, so both peers must advertise a window large
# enough that the segments never fall outside it -- scapy's 8192 default is not.
WINDOW = 65535

pkts = []
cseq, sseq = 1000, 5000


def c2s(flags, payload=b""):
    global cseq
    p = (
        Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
        / IP(src=CLIENT, dst=SERVER)
        / TCP(sport=SPORT, dport=DPORT, flags=flags, seq=cseq, ack=sseq, window=WINDOW)
    )
    if payload:
        p = p / Raw(payload)
    cseq += len(payload) + (1 if "S" in flags or "F" in flags else 0)
    pkts.append(p)


def s2c(flags, payload=b""):
    global sseq
    p = (
        Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
        / IP(src=SERVER, dst=CLIENT)
        / TCP(sport=DPORT, dport=SPORT, flags=flags, seq=sseq, ack=cseq, window=WINDOW)
    )
    if payload:
        p = p / Raw(payload)
    sseq += len(payload) + (1 if "S" in flags or "F" in flags else 0)
    pkts.append(p)


c2s("S")
s2c("SA")
c2s("A")

c2s("PA", to_server)
s2c("A")

# Server flight, segmented at the MSS.  The client ACKs every 4 segments, well
# inside the advertised window, so the stream engine keeps handing the TLS
# parser data across all ~140 segments.
for n, off in enumerate(range(0, len(to_client), MSS)):
    s2c("PA", to_client[off : off + MSS])
    if n % 4 == 3:
        c2s("A")
c2s("A")

c2s("FA")
s2c("FA")
c2s("A")

wrpcap("input.pcap", pkts)
print(f"cert: {len(cert)} bytes, {SAN_TOTAL} SANs")
print(f"server flight: {len(to_client)} bytes, {len(pkts)} packets")
