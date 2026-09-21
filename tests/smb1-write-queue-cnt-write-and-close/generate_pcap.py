#!/usr/bin/env python3
"""Craft the SMB1 write-queue-count-limit WRITE_AND_CLOSE regression pcap.

The SMB1 setup (negotiate / session / tree connect / create of the file on
FID 0x4001) is copied from the sibling test smb1-ooo-write-queue-size, which
carries a real parseable setup. On top of it four crafted WRITE records go
to the same FID:

- w1 (mid 0x201) WRITE_ANDX  offset   0, 100 x 0x41: in order (tracked 100)
- w2 (mid 0x202) WRITE_ANDX  offset 192, 100 x 0x42: out of order (queued)
- w3 (mid 0x203) WRITE_AND_CLOSE offset 224, 100 x 0x43: with the configured
  max-write-queue-cnt 1 the second queued chunk is rejected with
  write_queue_cnt_exceeded and the record remainder is skipped; the close
  command still runs and terminates the file transaction
- w4 (mid 0x204) WRITE_ANDX  offset   0, 100 x 0x44: the record after the
  rejected one, same FID; it must still be parsed (the skipped remainder of
  w3 did not eat its bytes)

Write record layout (as consumed by parse_smb_record +
parse_smb1_write_andx_request_record, andx_offset 32):

  NBSS   00 00 00 <len>           len = 32 + 31 + data_len
  SMB1   ff 53 4d 42 <cmd> <nt>4 <flags> <flags2>2 <pidh>2 <sig>8 <res>2
         <tree>2 <pid>2 <uid>2 <mid>2
  ANDX   <wct>1 <andx>1 <res>1 <andx_off>2 <fid>2 <offset>4 <res>4
         <mode>2 <rem>2 <dl_hi>2 <dl_lo>2 <data_off>2 <hi_off>4 <bcc>2
         data at data_off - 32 after the ANDX start (data_off 63)

The SMB1 header starts at payload offset 4 and spans 32 bytes, so the
command is at 8, the multiplex id ends the header at 34 and the ANDX
parameter block starts at 36 (andx_offset 32 from the header start).
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "..", "smb1-ooo-write-queue-size", "input.pcap")
OUT = os.path.join(HERE, "smb1-write-queue-cnt-write-and-close.pcap")

# offsets within the 8259-byte model write payload
O_NBSS_LEN = 1      # 3-byte BE length
O_CMD = 8
O_MID = 34
O_OFFSET = 43
O_DATALEN_LO = 57
O_DATA = 67
TPL_LEN = 8259


def read_pkts(path):
    f = open(path, "rb").read()
    magic, vmaj, vmin, tz, sz, network, linktype = struct.unpack("<IHHiIII", f[:24])
    off, idx, out = 24, 0, []
    while off < len(f):
        ts, tu, incl, orig = struct.unpack("<IIII", f[off:off + 16])
        off += 16
        out.append((ts, tu, f[off:off + incl]))
        off += incl
        idx += 1
    return (magic, vmaj, vmin, tz, sz, network, linktype), out


def tcp_hdr(sport, dport, seq, ack, flg, payload_len, win=64240):
    return struct.pack(">HHIIHHHH", sport, dport, seq, ack,
                       (5 << 12) | flg, win, 0, 0)


def csum16(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_tcp(src, dst, sport, dport, seq, ack, flg, payload, idno):
    t = tcp_hdr(sport, dport, seq, ack, flg, len(payload))
    t = t[:16] + struct.pack(">H", 0) + t[18:]  # zero the tcp csum (test -k none)
    pseudo = (bytes([0]) * 12) + struct.pack(">BBH", 0, 6, len(t))
    i = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(t) + len(payload), idno, 0, 64,
                    6, 0, bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + t
    i = i[:10] + struct.pack(">H", 0) + i[12:]  # zero the ip csum (test -k none)
    return i + payload


def make_write_andx(tpl, mid, offset, cmd, fill, n):
    p = bytearray(tpl[:O_DATA + n])
    nbss_len = 32 + 31 + n
    p[O_NBSS_LEN:O_NBSS_LEN + 3] = struct.pack(">I", nbss_len)[1:]
    p[O_CMD] = cmd
    p[O_MID:O_MID + 2] = struct.pack("<H", mid)
    p[O_OFFSET:O_OFFSET + 4] = struct.pack("<I", offset)
    p[O_DATALEN_LO:O_DATALEN_LO + 2] = struct.pack("<H", n)
    p[65:67] = struct.pack("<H", n)          # bcc
    p[O_DATA:O_DATA + n] = bytes([fill]) * n
    return bytes(p)


def make_write_and_close(tpl, mid, offset, fill, n):
    # classic (non-ANDX) WRITE_AND_CLOSE params: wct(1) fid(2) count(2)
    # offset(4) last_write(4) bcc(2), then the data
    p = bytearray(tpl[:4 + 32 + 15 + n])
    p[O_NBSS_LEN:O_NBSS_LEN + 3] = struct.pack(">I", 32 + 15 + n)[1:]
    p[O_CMD] = 0x2c
    p[O_MID:O_MID + 2] = struct.pack("<H", mid)
    a = 36
    p[a] = 1
    p[a + 1:a + 3] = b"\x01\x40"            # FID 0x4001
    p[a + 3:a + 5] = struct.pack("<H", n)   # count
    p[a + 5:a + 9] = struct.pack("<I", offset)
    p[a + 9:a + 13] = b"\x00" * 4          # last_write
    p[a + 13:a + 15] = struct.pack("<H", n)  # bcc
    p[a + 15:a + 15 + n] = bytes([fill]) * n
    return bytes(p)


def main():
    hdr, pkts = read_pkts(MODEL)
    setup = pkts[:19]              # handshake + SMB1 setup incl. the create
    tpl_payload = None
    for _, _, p in pkts:
        if p and p[0] == 0x45 and len(p) > 60 and p[9] == 6:
            ihl = (p[0] & 0x0f) * 4
            doff = ((p[ihl + 12] >> 4) & 0xf) * 4
            data = p[ihl + doff:]
            if len(data) == TPL_LEN:
                tpl_payload = data
                break
    assert tpl_payload is not None, "model write template not found"

    # client 42000 -> 445: writes; the client sequence resumes at the
    # template write's seq, the ack stays at the setup end
    cseq = 0x502
    sack = 0x244d
    out = list(setup)
    idno = 0x5020
    writes = [
        (0x201, 0, 0x2f, 0x41),
        (0x202, 192, 0x2f, 0x42),
        (0x203, 224, 0x2c, 0x43),
        (0x204, 0, 0x2f, 0x44),
    ]
    for mid, off, cmd, fill in writes:
        payload = (make_write_and_close(tpl_payload, mid, off, fill, 100)
                   if cmd == 0x2c else make_write_andx(tpl_payload, mid, off, cmd, fill, 100))
        out.append((0, 0, ip_tcp("10.0.2.1", "10.0.0.2", 42000, 445, cseq, sack, 0x10, payload, idno)))
        idno += 0x100
        cseq += len(payload)
        # plain ack back from the "server"
        out.append((0, 0, ip_tcp("10.0.0.2", "10.0.2.1", 445, 42000, sack, cseq, 0x10, b"", idno)))
        idno += 0x100

    blob = struct.pack("<IHHiIII", *hdr)
    for ts, tu, p in out:
        blob += struct.pack("<IIII", ts, tu, len(p), len(p)) + p
    open(OUT, "wb").write(blob)
    print("wrote", OUT, "packets", len(out))


if __name__ == "__main__":
    main()
