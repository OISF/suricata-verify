#!/usr/bin/env python3
"""Generate dnp3-log-limits.pcap: oversized DNP3 object, point and field lists.

One TCP flow with six application PDUs:

  1. G2V1 with 1000 points          -> points cut at 256
  2. 100 G1V1 objects               -> objects cut at 64
  3. G70V1 with a 9000-byte filename
                                    -> in-value truncation marker
  4. G70V2 with username and password
                                    -> password redacted
  5. G70V1 with a 9000-byte NUL data field
                                    -> in-value truncation marker
  6. G83V1 with a 9000-byte data_objects field
                                    -> base64 cut at 8192 raw bytes

The link frames are hand-built with the CRC-16/DNP3 algorithm of
src/app-layer-dnp3.c and split into transport segments the way the parser
expects (max 250 payload bytes per link frame).

Regenerate with: python3 create-pcap.py
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 5000
SERVER_PORT = 20000


# CRC-16/DNP3 table, same algorithm as src/app-layer-dnp3.c crc_table[].
def _make_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
            crc &= 0xFFFF
        table.append(crc)
    return table


TABLE = _make_table()


def crc16(block: bytes) -> int:
    crc = 0
    for b in block:
        crc = (TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)) & 0xFFFF
    return ~crc & 0xFFFF


def crc_bytes(block: bytes) -> bytes:
    crc = crc16(block)
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def link_header(length: int, control: int, dst: int, src: int) -> bytes:
    body = (
        bytes([0x05, 0x64, length, control])
        + dst.to_bytes(2, "little")
        + src.to_bytes(2, "little")
    )
    return body + crc_bytes(body)


def stuff(payload: bytes) -> bytes:
    """Insert a CRC16 after every 16-byte block of the post-header bytes."""
    out = b""
    for off in range(0, len(payload), 16):
        block = payload[off : off + 16]
        out += block + crc_bytes(block)
    return out


def segment(app_bytes: bytes, control: int = 0x04, dst: int = 100, src: int = 1):
    """Split an application PDU into link frames with transport headers."""
    frames = []
    buf = app_bytes
    seq = 0
    first = True
    while buf:
        chunk, buf = buf[:249], buf[249:]
        th = (0x40 if first else 0x00) | (0x80 if not buf else 0x00) | (seq & 0x3F)
        payload = bytes([th]) + chunk
        frames.append(link_header(5 + len(payload), control, dst, src) + stuff(payload))
        first = False
        seq += 1
    return frames


def pdu(function_code: int, objects: bytes) -> bytes:
    return bytes([0x81, function_code]) + objects


# 1000 G2V1 points (1 state byte each), qualifier 0x08: 2-octet count.
points_obj = (
    bytes([2, 1, 0x08]) + (1000).to_bytes(2, "little") + b"\x01" * 1000
)
points_pdu = pdu(21, points_obj)

# 100 G1V1 objects with one point each, qualifier 0x07: 1-octet count.
one_obj = bytes([1, 1, 0x07, 1, 1])
objects_pdu = pdu(21, one_obj * 100)

# G70V1 with a 9000-byte filename.
filename_obj = (
    bytes([70, 1, 0x07, 1])
    + (9000).to_bytes(2, "little")  # filename_size
    + bytes([1, 0])  # filetype_code, attribute_code
    + bytes(2)  # start_record
    + bytes(2)  # end_record
    + bytes(4)  # file_size
    + bytes(6)  # created_timestamp
    + bytes(2)  # permission
    + bytes(4)  # file_id
    + bytes(4)  # owner_id
    + bytes(4)  # group_id
    + bytes([3, 0])  # file_function_code, status_code
    + b"F" * 9000  # filename
    + (0).to_bytes(2, "little")  # data_size
)
filename_pdu = pdu(21, filename_obj)

# G70V1 with a 9000-byte NUL data field.
data_obj = (
    bytes([70, 1, 0x07, 1])
    + (0).to_bytes(2, "little")  # filename_size
    + bytes([1, 0])  # filetype_code, attribute_code
    + bytes(2)  # start_record
    + bytes(2)  # end_record
    + bytes(4)  # file_size
    + bytes(6)  # created_timestamp
    + bytes(2)  # permission
    + bytes(4)  # file_id
    + bytes(4)  # owner_id
    + bytes(4)  # group_id
    + bytes([3, 0])  # file_function_code, status_code
    + (9000).to_bytes(2, "little")  # data_size
    + b"\x00" * 9000  # data
)
data_pdu = pdu(21, data_obj)

# G70V2 with a username and a password.
username = b"alice"
password = b"hunter2"
auth_obj = (
    bytes([70, 2, 0x07, 1])
    + (0).to_bytes(2, "little")  # username_offset
    + len(username).to_bytes(2, "little")  # username_size
    + (0).to_bytes(2, "little")  # password_offset
    + len(password).to_bytes(2, "little")  # password_size
    + bytes(4)  # authentication_key
    + username
    + password
)
auth_pdu = pdu(21, auth_obj)

# G83V1 with a 9000-byte data_objects field.
blob = b"A" * 9000
vendor_obj = (
    bytes([83, 1, 0x07, 1])
    + b"TEST"
    + (0x1234).to_bytes(2, "little")  # object_id
    + len(blob).to_bytes(2, "little")  # length
    + blob
)
vendor_pdu = pdu(21, vendor_obj)

pkts = []
c_seq, s_seq = 1000, 2000
pkts.append(
    Ether(src=SRC_MAC, dst=DST_MAC)
    / IP(src=CLIENT_IP, dst=SERVER_IP)
    / TCP(
        sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=c_seq, window=65535
    )
)
pkts.append(
    Ether(src=DST_MAC, dst=SRC_MAC)
    / IP(src=SERVER_IP, dst=CLIENT_IP)
    / TCP(
        sport=SERVER_PORT,
        dport=CLIENT_PORT,
        flags="SA",
        seq=s_seq,
        ack=c_seq + 1,
        window=65535,
    )
)
pkts.append(
    Ether(src=SRC_MAC, dst=DST_MAC)
    / IP(src=CLIENT_IP, dst=SERVER_IP)
    / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=c_seq + 1, ack=s_seq + 1)
)
c_seq += 1
for app in (points_pdu, objects_pdu, filename_pdu, auth_pdu, data_pdu, vendor_pdu):
    for frame in segment(app):
        pkts.append(
            Ether(src=SRC_MAC, dst=DST_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / TCP(
                sport=CLIENT_PORT,
                dport=SERVER_PORT,
                flags="PA",
                seq=c_seq,
                ack=s_seq + 1,
            )
            / Raw(load=frame)
        )
        c_seq += len(frame)

wrpcap("dnp3-log-limits.pcap", pkts)
total = sum(len(p[Raw].load) for p in pkts if Raw in p)
print(f"wrote dnp3-log-limits.pcap: {len(pkts)} frames, {total} tcp-payload bytes")
