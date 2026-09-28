#!/usr/bin/env python3
"""Send TCP segments that Suricata normalizes inline, or check what arrives.

Raw sockets play both endpoints on addresses that no namespace owns, so the
kernels neither answer nor reset the traffic.

client: for each SIZES size, complete a handshake, then send segment A with
SIZE bytes and segment B, which overlaps the second half of A with SIZE bytes
that differ from the data of A at every stream offset.

server READY: answer the SYNs, record the segments arriving at the server
interface and require them with valid checksums: A intact, and B with the data
of A in the overlapping part.
"""

import collections
import socket
import struct
import sys
import time

CLIENT, SERVER = "10.200.0.3", "10.200.0.9"
PORT = 8080
SIZES = (400, 1400, 8960)
CLIENT_ISN, SERVER_ISN = 1000, 5000
SEQ = CLIENT_ISN + 1
SYN, PSH, ACK = 0x02, 0x08, 0x10
TCP = socket.IPPROTO_TCP

Segment = collections.namedtuple("Segment", "sport dport seq flags payload valid")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_checksum(src, dst, segment):
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, TCP,
                                                                          len(segment))
    return checksum(pseudo + segment)


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    csum = tcp_checksum(src, dst, header + payload)
    segment = header[:16] + struct.pack("!H", csum) + header[18:] + payload
    # the kernel fills in the IP header checksum
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000, 64, TCP, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + segment


def receiver(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    s.bind((iface, 0))
    s.settimeout(1)
    return s


def receive(s, src, dst):
    try:
        data = s.recv(65535)
    except socket.timeout:
        return None
    if data[9] != TCP or data[12:20] != socket.inet_aton(src) + socket.inet_aton(dst):
        return None
    header_len = (data[0] & 0x0F) * 4
    segment = data[header_len : struct.unpack_from("!H", data, 2)[0]]
    valid = checksum(data[:header_len]) == 0 and tcp_checksum(src, dst, segment) == 0
    sport, dport, seq, _, offset, flags = struct.unpack_from("!HHIIBB", segment)
    return Segment(sport, dport, seq, flags, segment[(offset >> 4) * 4 :], valid)


def stream(sender, start, end):
    """Return the data of a sender for a range of stream offsets."""
    data = bytes(offset % 251 for offset in range(start, end))
    return data if sender == "A" else bytes(255 - byte for byte in data)


def expected():
    """Return the payloads the server must receive by (source port, seq)."""
    result = {}
    for size in SIZES:
        half = size // 2
        result[(40000 + size, SEQ)] = stream("A", 0, size)
        result[(40000 + size, SEQ + half)] = stream("A", half, size) + stream("B", size,
                                                                              half + size)
    return result


def client():
    rx = receiver("client")
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    for size in SIZES:
        sport = 40000 + size
        half = size // 2
        tx.sendto(tcp(CLIENT, SERVER, sport, PORT, CLIENT_ISN, 0, SYN), (SERVER, 0))
        deadline = time.time() + 5
        while True:
            if time.time() > deadline:
                sys.exit(f"error: no SYN/ACK for the {size} byte session")
            s = receive(rx, SERVER, CLIENT)
            if s and (s.sport, s.dport, s.flags) == (PORT, sport, SYN | ACK):
                break
        ack = SERVER_ISN + 1
        tx.sendto(tcp(CLIENT, SERVER, sport, PORT, SEQ, ack, ACK), (SERVER, 0))
        tx.sendto(tcp(CLIENT, SERVER, sport, PORT, SEQ, ack, PSH | ACK, stream("A", 0, size)),
                  (SERVER, 0))
        tx.sendto(tcp(CLIENT, SERVER, sport, PORT, SEQ + half, ack, PSH | ACK,
                      stream("B", half, half + size)), (SERVER, 0))


def server(ready):
    rx = receiver("server")
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    open(ready, "w").close()

    wanted = expected()
    received = {}
    deadline = time.time() + 10
    while len(received) < len(wanted) and time.time() < deadline:
        s = receive(rx, CLIENT, SERVER)
        if s is None:
            continue
        if s.flags == SYN:
            tx.sendto(tcp(SERVER, CLIENT, s.dport, s.sport, SERVER_ISN, s.seq + 1, SYN | ACK),
                      (CLIENT, 0))
        elif s.payload:
            received[(s.sport, s.seq)] = s

    errors = 0
    for (sport, seq), payload in wanted.items():
        name = f"{sport - 40000} byte segment at seq {seq}"
        s = received.get((sport, seq))
        if s is None:
            print(f"error: {name} not received")
        elif s.payload != payload:
            print(f"error: {name} not received with the expected data")
        elif not s.valid:
            print(f"error: {name} received with an invalid checksum")
        else:
            continue
        errors += 1
    sys.exit(1 if errors else 0)


if sys.argv[1] == "client":
    client()
else:
    server(sys.argv[2])
