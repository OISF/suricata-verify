"""Common helpers for the NFS SV fixture generators (raw pcap, no deps)."""
import socket
import struct
import time


def be32(v):
    return struct.pack(">I", v)


def be64(v):
    return struct.pack(">Q", v)


def rpc_record(body):
    # is_last=1, frag_len=len(body)
    return struct.pack(">I", (1 << 31) | len(body)) + body


def fh3(data):
    return be32(len(data)) + data


def fh3p(data):
    # XDR length-prefixed string with 32-bit padding (nfsfname3/nfsace4)
    pad = (-len(data)) % 4
    return be32(len(data)) + data + b"\x00" * pad


def v3_fh(fill):
    # realistic 32-byte on-disk handle: type tag + data
    return fh3(b"\x01\x00\x00\x00" + bytes([fill]) * 28)


def unix_cred(uid=1000, gid=1000):
    cred = be32(0) + be32(0) + be32(uid) + be32(gid) + be32(0)
    return be32(1) + be32(len(cred)) + cred


def gss_cred(procedure, service, seqnum=1, ctx=b"\x00" * 16):
    # flavor 6 (RPCSEC_GSS): version 1 + procedure + seqnum + service + ctx
    body = be32(1) + be32(procedure) + be32(seqnum) + be32(service) + fh3(ctx)
    return be32(6) + be32(len(body)) + body


def null_verf():
    return be32(0) + be32(0)


def v3_call(xid, proc, prog_data):
    body = (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(3) + be32(proc)
        + unix_cred() + null_verf() + prog_data
    )
    return rpc_record(body)


def v3_reply(xid, prog_data):
    body = be32(xid) + be32(1) + be32(0) + null_verf() + be32(0) + prog_data
    return rpc_record(body)


def v4_call(xid, cred, prog_data):
    body = (
        be32(xid) + be32(0) + be32(2) + be32(100003) + be32(4) + be32(6)
        + cred + null_verf() + prog_data
    )
    return rpc_record(body)


def v4_reply(xid, prog_data):
    body = be32(xid) + be32(1) + be32(0) + null_verf() + be32(0) + prog_data
    return rpc_record(body)


def ip_checksum(hdr):
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def v4_ip(src, dst, proto, payload):
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), 0x1000, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    hdr = hdr[:10] + struct.pack(">H", ip_checksum(hdr)) + hdr[12:]
    return hdr + payload


class Pcap:
    """Minimal pcap writer; tracks TCP sequence numbers per direction."""

    def __init__(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.f = open(path, "ab")
        self.snd = {}
        self.ts = 0.0

    def tcp(self, src, dst, payload=b"", syn=False, synack=False, pure_ack=False):
        # src/dst are (ip, port) tuples
        self.ts += 0.00144
        key, rkey = src, dst
        if key not in self.snd:
            self.snd[key] = 1000
            self.snd[rkey] = 2000
        seq, ack = self.snd[key], self.snd[rkey]
        if syn:
            flags = 0x02
        elif synack:
            flags = 0x12
        elif pure_ack:
            flags = 0x10
        else:
            flags = 0x18
        if syn or synack:
            self.snd[key] += 1
        if payload:
            self.snd[key] += len(payload)
        tcp = struct.pack(
            ">HHIIHHHH", src[1], dst[1], seq, ack,  (5 << 12) | flags, 64240, 0, 0
        )
        ip = v4_ip(src[0], dst[0], 6, tcp + payload)
        eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
        caplen = len(eth) + len(ip)
        self.f.write(
            struct.pack("<IIII", 0, int(self.ts * 1e6), caplen, caplen) + eth + ip
        )

    def close(self):
        self.f.close()
