#!/usr/bin/env python3
"""Craft NBSS-wrapped SMB2 WRITE request records that grow the out-of-order
queue past the file-data backstop on a stream that never gaps.

The backstop (rust/src/smb/files.rs::filetracker_update) caps the queued OOO
data of every open file tx. Main merged in September runs it only after a
stream gap, so a gapless stream can queue chunks forever; the branch runs it
whenever a call carries file data, which is what this capture drives.

Limits are turned off in the config (max-write-queue-cnt: 0), so the per
enqueue check never rejects and the hard chunk-count backstop (1024) is the
only cap. That means the capture has to queue more than 1024 chunks:

- w1 (msg 1) offset 0, 100 bytes: in order, opens the file tx (tracked 100).
- q2..q1051 (msg 2..1051) offsets 200..1249, 1 byte each: out of order, one
  new queued chunk each. Nothing fills the 100..200 hole, so no chunk ever
  drains and no stream gap is seen.
- w2 (msg 1052) offset 100, 100 bytes: the first call that carries data after
  the queue went over the cap. The backstop fires here: the file is truncated
  (applayer/smb/truncated_file_data on the file tx) and w2 is consumed but
  not stored, so the stored file stays the 100 bytes of w1.

The data packets advertise a large window and the server ACKs periodically:
a 123 KiB to-server stream is otherwise cut short by the TCP window tracking
long before the queue grows.

NBSS record: type byte 0x00 (SESSION_MESSAGE) + 3-byte BE length, then the
SMB2 message.
"""
import hashlib
import sys
from scapy.all import IP, TCP, Raw, wrpcap

SMB2_COMMAND_WRITE = 0x0009
# queued chunks needed: the hard chunk-count backstop is 1024
QUEUE_CHUNKS = 1050


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


def write_record(guid, offset, data, msg_id):
    return nbss_record(smb2_header(SMB2_COMMAND_WRITE, msg_id)
                       + smb2_write_body(guid, offset, len(data), data))


def main():
    guid = bytes([0xAA, 0xBB, 0xCC, 0xDD] + [0] * 12)
    src, dst, sp, dp = "192.168.1.1", "192.168.1.2", 12345, 445
    # the window has to cover the whole 123 KiB stream
    win = 65535
    seq_c, seq_s = 1000, 2000
    pkts = []
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="S",
                                           seq=seq_c, ack=0, window=win))
    pkts.append(IP(src=dst, dst=src) / TCP(sport=dp, dport=sp, flags="SA",
                                           seq=seq_s - 1, ack=seq_c + 1, window=win))
    seq_c += 1  # SYN consumed one byte
    pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="A",
                                           seq=seq_c, ack=seq_s, window=win))

    def emit(payload):
        nonlocal seq_c
        pkts.append(IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="PA",
                                               seq=seq_c, ack=seq_s,
                                               window=win) / Raw(load=payload))
        seq_c += len(payload)

    def ack():
        """server acknowledges: keeps the window tracking from cutting the
        long to-server stream short"""
        pkts.append(IP(src=dst, dst=src) / TCP(sport=dp, dport=sp, flags="A",
                                               seq=seq_s, ack=seq_c, window=win))

    records = [write_record(guid, 0, b"A" * 100, 1)]
    for i in range(QUEUE_CHUNKS):
        records.append(write_record(guid, 200 + i, b"Q", 2 + i))
    records.append(write_record(guid, 100, b"F" * 100, QUEUE_CHUNKS + 2))

    for i, rec in enumerate(records):
        emit(rec)
        if i % 50 == 49:
            ack()

    out = sys.argv[1] if len(sys.argv) > 1 else "input.pcap"
    wrpcap(out, pkts)
    print(f"wrote {out}: {len(records)} write records "
          f"({QUEUE_CHUNKS} queued OOO chunks)")
    print("expected stored file sha256 once the backstop fires (w1 only):",
          hashlib.sha256(b"A" * 100).hexdigest())


if __name__ == "__main__":
    main()
