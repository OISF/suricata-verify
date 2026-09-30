#!/usr/bin/env python3
"""Send traffic that Suricata modifies inline, or check what arrives.

Raw sockets play both endpoints on addresses that no namespace owns, so the
kernels neither answer nor reset the traffic.

client: send a UDP datagram of each UDP_SIZES size, ending with the bytes a
rule replaces. For each TCP_SIZES size, complete a handshake, then send
segment A with SIZE bytes of "A" and segment B, which overlaps the second half
of A with SIZE bytes of "B".

server READY: answer the SYNs, record the datagrams and segments arriving at
the server interface and require them to carry Suricata's modifications with
valid checksums: the replaced bytes, and the data of A in the overlapping part
of B.
"""

import collections
import socket
import struct
import sys
import time

CLIENT, SERVER = "10.200.0.3", "10.200.0.9"
UDP_PORT, TCP_PORT = 7777, 8080
UDP_SIZES, TCP_SIZES = (500, 8972), (400, 1400)
CLIENT_ISN, SERVER_ISN = 1000, 5000
SEQ = CLIENT_ISN + 1
SYN, PSH, ACK = 0x02, 0x08, 0x10
UDP, TCP = socket.IPPROTO_UDP, socket.IPPROTO_TCP
PATTERN, REPLACED = b"\xde\xad\xbe\xef", b"\xca\xfe\xba\xbe"

Segment = collections.namedtuple("Segment", "proto sport dport seq flags payload valid")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def transport_checksum(proto, src, dst, segment):
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto,
                                                                          len(segment))
    return checksum(pseudo + segment)


def ip(proto, src, dst, segment):
    # the kernel fills in the IP header checksum
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + segment


def udp(src, dst, sport, dport, payload):
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = transport_checksum(UDP, src, dst, header + payload) or 0xFFFF
    return ip(UDP, src, dst, header[:6] + struct.pack("!H", csum) + payload)


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    csum = transport_checksum(TCP, src, dst, header + payload)
    return ip(TCP, src, dst, header[:16] + struct.pack("!H", csum) + header[18:] + payload)


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
    if data[12:16] != socket.inet_aton(src) or data[16:20] != socket.inet_aton(dst):
        return None
    proto = data[9]
    segment = data[(data[0] & 0x0F) * 4 : struct.unpack_from("!H", data, 2)[0]]
    valid = transport_checksum(proto, src, dst, segment) == 0
    if proto == UDP:
        sport, dport = struct.unpack_from("!HH", segment)
        return Segment(proto, sport, dport, 0, 0, segment[8:], valid)
    if proto == TCP:
        sport, dport, seq, _, offset, flags = struct.unpack_from("!HHIIBB", segment)
        return Segment(proto, sport, dport, seq, flags, segment[(offset >> 4) * 4 :], valid)
    return None


def expected():
    """Return the payloads the server must receive by (protocol, source port, seq)."""
    result = {}
    for size in UDP_SIZES:
        result[(UDP, 40000 + size, 0)] = b"A" * (size - len(REPLACED)) + REPLACED
    for size in TCP_SIZES:
        half = size // 2
        result[(TCP, 40000 + size, SEQ)] = b"A" * size
        result[(TCP, 40000 + size, SEQ + half)] = b"A" * half + b"B" * (size - half)
    return result


def describe(key):
    proto, sport, seq = key
    if proto == UDP:
        return f"{sport - 40000} byte datagram"
    return f"{sport - 40000} byte segment at seq {seq}"


def client():
    rx = receiver("client")
    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    for size in UDP_SIZES:
        payload = b"A" * (size - len(PATTERN)) + PATTERN
        tx.sendto(udp(CLIENT, SERVER, 40000 + size, UDP_PORT, payload), (SERVER, 0))

    for size in TCP_SIZES:
        sport = 40000 + size
        tx.sendto(tcp(CLIENT, SERVER, sport, TCP_PORT, CLIENT_ISN, 0, SYN), (SERVER, 0))
        deadline = time.time() + 5
        while True:
            if time.time() > deadline:
                sys.exit(f"error: no SYN/ACK for the {size} byte session")
            s = receive(rx, SERVER, CLIENT)
            if s and s.proto == TCP and (s.sport, s.dport, s.flags) == (TCP_PORT, sport,
                                                                         SYN | ACK):
                break
        ack = SERVER_ISN + 1
        tx.sendto(tcp(CLIENT, SERVER, sport, TCP_PORT, SEQ, ack, ACK), (SERVER, 0))
        tx.sendto(tcp(CLIENT, SERVER, sport, TCP_PORT, SEQ, ack, PSH | ACK, b"A" * size),
                  (SERVER, 0))
        tx.sendto(tcp(CLIENT, SERVER, sport, TCP_PORT, SEQ + size // 2, ack, PSH | ACK,
                      b"B" * size), (SERVER, 0))


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
        if s.proto == TCP and s.flags == SYN:
            tx.sendto(tcp(SERVER, CLIENT, s.dport, s.sport, SERVER_ISN, s.seq + 1, SYN | ACK),
                      (CLIENT, 0))
        elif s.payload:
            received[(s.proto, s.sport, s.seq)] = s

    errors = 0
    for key, payload in wanted.items():
        s = received.get(key)
        if s is None:
            print(f"error: {describe(key)} not received")
        elif s.payload != payload:
            print(f"error: {describe(key)} not received with the expected data")
        elif not s.valid:
            print(f"error: {describe(key)} received with an invalid checksum")
        else:
            continue
        errors += 1
    sys.exit(1 if errors else 0)


if sys.argv[1] == "client":
    client()
else:
    server(sys.argv[2])
