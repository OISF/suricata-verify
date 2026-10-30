"""Shared code for the pcaps of the dnp3-tcp-gap-* tests.

Writes classic little-endian pcap files (Ethernet, IPv4, TCP) with valid IP and TCP
checksums. Each pcap holds long-lived connections from masters 10.128.0.{k} (port 1024)
to an outstation or server at 10.0.0.2: the TCP handshake, then marked request/response
transactions, then FIN/ACK.

Two workloads, both one marked request per transaction:
  - dnp3 (port 20000): a Read of group 30 variation 1, qualifier 0x02, start = stop =
    marker, and the outstation's empty Response (function 0x81). Link layer with header
    and per-block CRCs, transport FIR|FIN, sequence numbers per connection.
  - modbus (port 502): Read Holding Registers of one register; the marker's low 16 bits
    are the transaction id and its high 16 bits the start address. The response returns
    one register.

Transaction m goes to connection m mod CONNS. With split > 0, every application frame
(requests and responses) travels in two TCP segments, the first `split` bytes long.

One data segment of connection 0 can be left out, so that the monitor sees a TCP gap: the
whole request or response `lost_request` of that connection, its second half, or its first
half. generate_wrap builds the multi-frame fragment case described in its docstring.
"""
import struct

CRC_POLY = 0xA6BC  # DNP3 CRC-16, reflected form of 0x3D65


def dnp3_crc(b):
    c = 0
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ CRC_POLY if c & 1 else c >> 1
    return (~c) & 0xFFFF


def dnp3_frame(ctl, dest, src, user):
    h = bytes([0x05, 0x64, 5 + len(user), ctl]) + struct.pack('<HH', dest, src)
    out = h + struct.pack('<H', dnp3_crc(h))
    while user:
        b, user = user[:16], user[16:]
        out += b + struct.pack('<H', dnp3_crc(b))
    return out


def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip(a):
    return bytes(int(x) for x in a.split('.'))


class Pcap:
    def __init__(self, path):
        self.f = open(path, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.us = 0

    def packet(self, src, dst, sport, dport, seq, ack, flags, payload=b''):
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
        pseudo = _ip(src) + _ip(dst) + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', _csum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, _ip(src), _ip(dst))
        ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
        frame = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + tcp
        self.us += 200
        self.f.write(struct.pack('<IIII', self.us // 1_000_000, self.us % 1_000_000, len(frame), len(frame)) + frame)

    def close(self):
        self.f.close()


class Conn:
    def __init__(self, pcap, k, port):
        self.p, self.cli, self.srv, self.port = pcap, f'10.128.0.{k}', '10.0.0.2', port
        self.cseq, self.sseq = 1000, 5000
        self.tseq_m = self.aseq = self.tseq_o = 0

    def handshake(self):
        p = self.p
        p.packet(self.cli, self.srv, 1024, self.port, self.cseq, 0, 0x02)
        p.packet(self.srv, self.cli, self.port, 1024, self.sseq, self.cseq + 1, 0x12)
        self.cseq += 1
        self.sseq += 1
        p.packet(self.cli, self.srv, 1024, self.port, self.cseq, self.sseq, 0x10)

    def send(self, from_client, data, lost=False):
        """One data segment; a lost one advances the sequence number but is not written."""
        if from_client:
            if not lost:
                self.p.packet(self.cli, self.srv, 1024, self.port, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)
        else:
            if not lost:
                self.p.packet(self.srv, self.cli, self.port, 1024, self.sseq, self.cseq, 0x18, data)
            self.sseq += len(data)

    def finish(self):
        p = self.p
        p.packet(self.cli, self.srv, 1024, self.port, self.cseq, self.sseq, 0x11)
        p.packet(self.srv, self.cli, self.port, 1024, self.sseq, self.cseq + 1, 0x11)
        p.packet(self.cli, self.srv, 1024, self.port, self.cseq + 1, self.sseq + 1, 0x10)


def segments(frame, split):
    if split <= 0 or split >= len(frame):
        return [frame]
    return [frame[:split], frame[split:]]


def dnp3_request(c, marker):
    user = bytes([0xC0 | c.tseq_m, 0xC0 | c.aseq, 0x01, 30, 1, 0x02]) + struct.pack('<II', marker, marker)
    c.tseq_m = (c.tseq_m + 1) & 0x3F
    return dnp3_frame(0xC4, 10, 1, user)


def dnp3_response(c):
    user = bytes([0xC0 | c.tseq_o, 0xC0 | c.aseq, 0x81, 0x00, 0x00])
    c.tseq_o = (c.tseq_o + 1) & 0x3F
    c.aseq = (c.aseq + 1) & 0x0F
    return dnp3_frame(0x44, 1, 10, user)


def mbap(tid, pdu, unit=1):
    return struct.pack('!HHHB', tid, 0, 1 + len(pdu), unit) + pdu


def modbus_request(marker):
    return mbap(marker & 0xFFFF, struct.pack('!BHH', 3, marker >> 16, 1))


def modbus_response(marker):
    return mbap(marker & 0xFFFF, struct.pack('!BBH', 3, 2, marker & 0xFFFF))


def generate(path, proto, case, conns=4, transactions=2000, lost_request=99, direction='request'):
    """case: 'whole' (frame lost whole), 'split' (second half lost), 'head' (first half
    lost), or 'none'. lost_request is the 0-based index of the transaction on connection 0;
    direction says whether its request or its response loses the segment."""
    port = 20000 if proto == 'dnp3' else 502
    split = 0 if case in ('whole', 'none') else (10 if proto == 'dnp3' else 6)
    p = Pcap(path)
    cs = [Conn(p, k, port) for k in range(conns)]
    for c in cs:
        c.handshake()

    def lost(m, i):
        return (m % conns == 0 and m // conns == lost_request and case != 'none' and
                (case == 'whole' or (case == 'split' and i == 1) or (case == 'head' and i == 0)))

    for m in range(transactions):
        c = cs[m % conns]
        req = dnp3_request(c, m) if proto == 'dnp3' else modbus_request(m)
        for i, s in enumerate(segments(req, split)):
            c.send(True, s, direction == 'request' and lost(m, i))
        resp = dnp3_response(c) if proto == 'dnp3' else modbus_response(m)
        for i, s in enumerate(segments(resp, split)):
            c.send(False, s, direction == 'response' and lost(m, i))
    for c in cs:
        c.finish()
    p.close()


def generate_fragment(path, case, reads=200):
    """DNP3 on one connection: `reads` marked Reads; before Read 100 the master sends a
    WRITE of three 200-octet strings (group 110 var 200, qualifier 0x00, indexes 0-2), a
    607-octet application fragment in three link frames, one per TCP segment.
    case: 'none', 'first-lost' (whole first frame), 'middle-lost' (whole middle frame),
    'middle-half' (second half of the middle frame)."""
    p = Pcap(path)
    c = Conn(p, 0, 20000)
    c.handshake()
    for m in range(reads):
        if m == 100:
            app = bytes([0xC0 | c.aseq, 0x02, 110, 200, 0x00, 0, 2]) + bytes(range(200)) * 3
            chunks = [app[k:k + 249] for k in range(0, len(app), 249)]
            for j, ch in enumerate(chunks):
                th = c.tseq_m | (0x40 if j == 0 else 0) | (0x80 if j == len(chunks) - 1 else 0)
                c.tseq_m = (c.tseq_m + 1) & 0x3F
                f = dnp3_frame(0xC4, 10, 1, bytes([th]) + ch)
                if case == 'first-lost' and j == 0 or case == 'middle-lost' and j == 1:
                    c.send(True, f, lost=True)
                elif case == 'middle-half' and j == 1:
                    c.send(True, f[:100])
                    c.send(True, f[100:], lost=True)
                else:
                    c.send(True, f)
            c.send(False, dnp3_response(c))
        c.send(True, dnp3_request(c, m))
        c.send(False, dnp3_response(c))
    c.finish()
    p.close()


def generate_wrap(path):
    """DNP3 on one connection. The master sends a WRITE of 120 points of group 30 variation
    1 (qualifier 0x01, indexes 0-119, every octet `fill`): a 609-octet application fragment
    in three link frames with transport sequence numbers s, s+1, s+2, one per TCP segment. The
    middle segment is lost. 61 single-frame Reads follow, so the next WRITE (another
    three-frame fragment, with a different fill) again uses s, s+1, s+2: its
    second and third frames carry the sequence numbers that the first, unfinished WRITE
    expects next. Ten more Reads follow."""
    p = Pcap(path)
    c = Conn(p, 0, 20000)
    c.handshake()
    marker = 0

    def write(fill, lose_middle):
        app = bytes([0xC0 | c.aseq, 0x02, 30, 1, 0x01]) + struct.pack('<HH', 0, 119) + bytes([fill]) * 600
        chunks = [app[k:k + 249] for k in range(0, len(app), 249)]
        for j, ch in enumerate(chunks):
            th = c.tseq_m | (0x40 if j == 0 else 0) | (0x80 if j == len(chunks) - 1 else 0)
            c.tseq_m = (c.tseq_m + 1) & 0x3F
            c.send(True, dnp3_frame(0xC4, 10, 1, bytes([th]) + ch), lost=lose_middle and j == 1)
        c.send(False, dnp3_response(c))

    def read():
        nonlocal marker
        c.send(True, dnp3_request(c, marker))
        c.send(False, dnp3_response(c))
        marker += 1

    for _ in range(5):
        read()
    write(0x41, True)
    for _ in range(61):
        read()
    write(0x42, False)
    for _ in range(10):
        read()
    c.finish()
    p.close()
