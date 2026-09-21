#!/usr/bin/env python3
"""Craft NBSS-wrapped SMB2 WRITE request records with the rejected WRITE
split across two TCP segments, matching
rust/src/smb/{nbss_records,smb2_records,smb2}.rs parsers.

Unlike smb2-ooo-write-queue-cnt (where every write is a complete NBSS
record in one packet, taking the complete-record path), the rejected w5
here straddles a segment boundary: the first segment carries the SMB2
header + write body + part of the data (>= 512 bytes, so the parser
enters parse_tcp_data_ts_partial with wr.data.len() < wr.wr_len) and the
second segment carries the w5 remainder plus the in-order w6. This is
the path where a queue-limit-rejected record must skip its remainder
without its trailing file-data promise double-claiming the next record's
bytes.

NBSS record: type byte 0x00 (SESSION_MESSAGE) + 3-byte BE length, then
the SMB2 message.
"""
import hashlib
import sys
from scapy.all import IP, TCP, Raw, wrpcap

SMB2_COMMAND_WRITE = 0x0009


def smb2_header(command, msg_id):
    hdr = b"\xfeSMB"                      # 0-3 magic
    hdr += (64).to_bytes(2, "little")     # 4-5 header length
    hdr += (0).to_bytes(2, "little")     # 6-7 credit charge
    hdr += (0).to_bytes(2, "little")     # 8-9 channel seq
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


def write_record(guid, offset, data, msg_id):
    return nbss_record(smb2_header(SMB2_COMMAND_WRITE, msg_id)
                       + smb2_write_body(guid, offset, len(data), data))


def main():
    # max-write-queue-cnt is 3 (see suricata.yaml): w1 fills in order
    # (tracked 100); w2..w4 queue 3 OOO chunks; w5 (split across two
    # segments) would add a 4th (3 + 1 > 3) and is rejected on the
    # partial path -> write_queue_cnt_exceeded; w6 at the tracked offset
    # must still land in order and the stream must stay in sync.
    guid = bytes([0xAA, 0xBB, 0xCC, 0xDD] + [0] * 12)
    src, dst, sp, dp = "192.168.1.1", "192.168.1.2", 12345, 445
    pkts = []
    seq_c, seq_s = 1000, 2000
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="S", seq=seq_c, ack=0))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dp, dport=sp, flags="SA", seq=seq_s - 1, ack=seq_c + 1))
    seq_c += 1  # SYN consumed one byte
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="A", seq=seq_c, ack=seq_s))

    def emit(payload):
        nonlocal seq_c
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="PA",
                                               seq=seq_c, ack=seq_s) / Raw(load=payload))
        seq_c += len(payload)

    for i, (off, data) in enumerate([(0, b"A" * 100),
                                     (300, b"B" * 100),
                                     (400, b"C" * 100),
                                     (500, b"D" * 100)]):
        emit(write_record(guid, off, data, i + 1))

    w5 = write_record(guid, 600, b"X" * 700, 5)   # rejected, split
    w6 = write_record(guid, 100, b"E" * 100, 6)   # in order after w5
    # segment 1: header + body + 444 of 700 data (560 bytes >= 512, so
    # the partial-record path is taken with wr.data.len() < wr.wr_len)
    emit(w5[:560])
    # segment 2: the w5 remainder plus the complete w6 record
    emit(w5[560:] + w6)

    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    wrpcap(out, pkts)
    print(f"wrote {out}: 6 write records (w5 split {560}/{len(w5) - 560})")
    print("expected stored file sha256 (rejected chunk never stored):",
          hashlib.sha256(b"A" * 100 + b"E" * 100).hexdigest())


if __name__ == "__main__":
    main()
