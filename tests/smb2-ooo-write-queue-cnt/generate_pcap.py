#!/usr/bin/env python3
"""Craft NBSS-wrapped SMB2 WRITE request records matching
rust/src/smb/{nbss_records,smb2_records}.rs parsers.

NBSS record: type byte 0x00 (SESSION_MESSAGE) + 3-byte BE length,
then the SMB2 message.

SMB2 header field order matches parse_smb2_request_record:
magic | hlen u16 | credit u16 | chan u16 | res u16 | cmd u16 |
credits u16 | flags u32 | chain u32 | msg_id u64 | pid u32 |
tree u32 | sess u64 | sig[16]
"""
import hashlib
import sys
from scapy.all import IP, TCP, Raw, wrpcap

SMB2_COMMAND_WRITE = 0x0009


def smb2_header(command, msg_id):
    hdr = b"\xfeSMB"                      # 0-3 magic
    hdr += (64).to_bytes(2, "little")     # 4-5 header length
    hdr += (0).to_bytes(2, "little")      # 6-7 credit charge
    hdr += (0).to_bytes(2, "little")      # 8-9 channel seq
    hdr += b"\x00\x00"                    # 10-11 reserved
    hdr += command.to_bytes(2, "little")  # 12-13 command
    hdr += (0).to_bytes(2, "little")      # 14-15 credits requested
    hdr += (0).to_bytes(4, "little")      # 16-19 flags (bit0=response)
    hdr += (0).to_bytes(4, "little")      # 20-23 chain offset (0 -> rest)
    hdr += msg_id.to_bytes(8, "little")   # 24-31 message id
    hdr += (0).to_bytes(4, "little")      # 32-35 process id
    hdr += (0).to_bytes(4, "little")      # 36-39 tree id
    hdr += (0).to_bytes(8, "little")      # 40-47 session id
    hdr += b"\x00" * 16                   # 48-63 signature
    assert len(hdr) == 64, len(hdr)
    return hdr


def smb2_write_body(guid, offset, length, data):
    # layout matches parse_smb2_request_write
    body = b"\x32\x00\x00\x00"            # struct size + pad (skip4)
    body += int(length).to_bytes(4, "little")
    body += int(offset).to_bytes(8, "little")
    body += guid                          # 16 byte file guid
    body += (0).to_bytes(4, "little")     # channel
    body += (0).to_bytes(4, "little")     # remaining bytes
    body += (0).to_bytes(4, "little")     # write flags
    body += b"\x00\x00\x00\x00"           # skip2
    return body + data


def nbss_record(smb2_msg):
    return b"\x00" + len(smb2_msg).to_bytes(3, "big") + smb2_msg


def write_record(guid, offset, data, msg_id, declared_len=None):
    body = smb2_write_body(guid, offset,
                           len(data) if declared_len is None else declared_len,
                           data)
    return nbss_record(smb2_header(SMB2_COMMAND_WRITE, msg_id) + body)


def build(pcap_path, writes):
    """writes: list of (guid, offset, data[, declared_len]); 3whs prepended."""
    src, dst, sp, dp = "192.168.1.1", "192.168.1.2", 12345, 445
    pkts = []
    seq_c, seq_s = 1000, 2000
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="S", seq=seq_c, ack=0))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dp, dport=sp, flags="SA", seq=seq_s - 1, ack=seq_c + 1))
    seq_c += 1  # SYN consumed one byte
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="A", seq=seq_c, ack=seq_s))
    for i, w in enumerate(writes):
        guid, offset, data = w[0], w[1], w[2]
        declared = w[3] if len(w) > 3 else None
        rec = write_record(guid, offset, data, i + 1, declared)
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="PA", seq=seq_c, ack=seq_s) / Raw(load=rec))
        seq_c += len(rec)
    wrpcap(pcap_path, pkts)
    print(f"wrote {pcap_path}: {len(writes)} write records")

if __name__ == "__main__":
    # max-write-queue-cnt is 3 (see suricata.yaml): w1 fills in order
    # (tracked 100); w2..w4 queue 3 OOO chunks; w5 would add a 4th
    # (3 + 1 > 3) and is rejected -> write_queue_cnt_exceeded on the
    # file tx; w6 at the tracked offset still lands in order and the
    # stream stays in sync.
    guid = bytes([0xAA, 0xBB, 0xCC, 0xDD] + [0] * 12)
    writes = [
        (guid, 0, b"A" * 100),
        (guid, 300, b"B" * 100),
        (guid, 400, b"C" * 100),
        (guid, 500, b"D" * 100),
        (guid, 600, b"X" * 100),  # rejected: 3 + 1 > 3
        (guid, 100, b"E" * 100),  # in order after the rejection
    ]
    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    build(out, writes)
    print("expected stored file sha256 (rejected chunk never stored):",
          hashlib.sha256(b"A" * 100 + b"E" * 100).hexdigest())
