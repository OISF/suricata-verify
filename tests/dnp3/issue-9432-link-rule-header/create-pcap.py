#!/usr/bin/env python3
"""Generate input.pcap: DNP3 over TCP, master 1 -> outstation 10, port 20000.

Each flow carries one TCP segment that ends in the same valid DIRECT_OPERATE
frame (CROB, index 3). Before it, a 10-octet link header with a valid CRC:

  10.0.0.1  none (control)
  10.0.1.1  0xC9 REQUEST_LINK_STATUS with LENGTH 60 (no user data allowed)
  10.0.2.1  0xC9 REQUEST_LINK_STATUS with LENGTH 255
  10.0.3.1  0xC0 RESET_LINK_STATES with LENGTH 60
  10.0.4.1  0xD4 UNCONFIRMED_USER_DATA with FCV set, LENGTH 60
  10.0.5.1  0xC7 reserved primary function code, LENGTH 60
  10.0.6.1  0xC9 REQUEST_LINK_STATUS with LENGTH 5 (valid, control)
  10.0.7.1  0xD2 TEST_LINK_STATES with FCV set, LENGTH 5 (valid, control)

Flows 1-5 break a link-layer rule. A DNP3 device such as opendnp3 discards
such a header when it reads it, resynchronizes on the next start bytes and
executes the DIRECT_OPERATE.
"""

import struct

from scapy.all import IP, TCP, Ether, Raw, wrpcap


def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return ~c & 0xFFFF


def header(control, length):
    h = bytes([0x05, 0x64, length, control, 0x0A, 0x00, 0x01, 0x00])
    return h + struct.pack("<H", crc(h))


assert header(0xC9, 60).hex() == "05643cc90a000100867c"

DIRECT_OPERATE = bytes.fromhex(
    "056418c40a0001003d3ac1c1050c0117010803016400000064007610000000ffff"
)

FLOWS = [
    ("10.0.0.1", b""),
    ("10.0.1.1", header(0xC9, 60)),
    ("10.0.2.1", header(0xC9, 255)),
    ("10.0.3.1", header(0xC0, 60)),
    ("10.0.4.1", header(0xD4, 60)),
    ("10.0.5.1", header(0xC7, 60)),
    ("10.0.6.1", header(0xC9, 5)),
    ("10.0.7.1", header(0xD2, 5)),
]


def flow(client, payload, sport, t0):
    server = client[:-1] + "2"
    c2s = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(
        src=client, dst=server
    )
    s2c = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01") / IP(
        src=server, dst=client
    )
    cs, ss = 1000, 2000
    pkts = [
        c2s / TCP(sport=sport, dport=20000, seq=cs, flags="S"),
        s2c / TCP(sport=20000, dport=sport, seq=ss, ack=cs + 1, flags="SA"),
    ]
    cs += 1
    ss += 1
    pkts.append(c2s / TCP(sport=sport, dport=20000, seq=cs, ack=ss, flags="A"))
    pkts.append(
        c2s / TCP(sport=sport, dport=20000, seq=cs, ack=ss, flags="PA") / Raw(payload)
    )
    cs += len(payload)
    pkts.append(s2c / TCP(sport=20000, dport=sport, seq=ss, ack=cs, flags="A"))
    pkts.append(c2s / TCP(sport=sport, dport=20000, seq=cs, ack=ss, flags="FA"))
    cs += 1
    pkts.append(s2c / TCP(sport=20000, dport=sport, seq=ss, ack=cs, flags="FA"))
    ss += 1
    pkts.append(c2s / TCP(sport=sport, dport=20000, seq=cs, ack=ss, flags="A"))
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.01
    return pkts


packets = []
for i, (client, prefix) in enumerate(FLOWS):
    packets += flow(client, prefix + DIRECT_OPERATE, 10001 + i, 1 + i * 100)
wrpcap("input.pcap", packets)
