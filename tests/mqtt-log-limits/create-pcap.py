#!/usr/bin/env python3
"""Generate mqtt-log-limits.pcap: oversized MQTT fields and arrays.

One MQTT v3.1.1 session:
  1. CONNECT with a 60000-byte protocol string and a password
  2. SUBSCRIBE + SUBACK with 100 return codes   -> qos_granted cut at 64
  3. PUBLISH with a 2000-byte NUL payload       -> in-value marker
  4. UNSUBSCRIBE with two 1000-byte topics + UNSUBACK
                                                -> topic budget cut

Regenerate with: python3 create-pcap.py
"""

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 5000
SERVER_PORT = 1883


def varint(n: int) -> bytes:
    out = b""
    while True:
        b = n % 128
        n //= 128
        if n:
            b |= 0x80
        out += bytes([b])
        if not n:
            return out


def mqtt_str(s: bytes) -> bytes:
    assert len(s) <= 0xFFFF
    return len(s).to_bytes(2, "big") + s


def mqtt_pkt(fixed: int, body: bytes) -> bytes:
    return bytes([fixed]) + varint(len(body)) + body


# CONNECT: protocol string "MQTT" followed by 59996 filler bytes.
connect = mqtt_pkt(
    0x10,
    mqtt_str(b"MQTT" + b"A" * 59996)
    + bytes([4, 0xC2])  # level 4, clean session, username+password
    + (60).to_bytes(2, "big")  # keepalive
    + mqtt_str(b"client1")
    + mqtt_str(b"user")
    + mqtt_str(b"hunter2"),
)
connack = mqtt_pkt(0x20, b"\x00\x00")
subscribe = mqtt_pkt(0x82, (1).to_bytes(2, "big") + mqtt_str(b"topic/a") + bytes([0]))
suback = mqtt_pkt(0x90, (1).to_bytes(2, "big") + bytes(100))
publish = mqtt_pkt(0x30, mqtt_str(b"topic/t") + b"\x00" * 2000)
unsubscribe = mqtt_pkt(0xA2, (2).to_bytes(2, "big") + mqtt_str(b"t" * 1000) * 2)
unsuback = mqtt_pkt(0xB0, (2).to_bytes(2, "big"))

pkts = []
c_seq, s_seq = 1000, 2000
pkts.append(
    Ether(src=SRC_MAC, dst=DST_MAC)
    / IP(src=CLIENT_IP, dst=SERVER_IP)
    / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=c_seq, window=65535)
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
s_seq += 1

for client_data, server_data in (
    (connect, connack),
    (subscribe, suback),
    (publish, None),
    (unsubscribe, unsuback),
):
    pkts.append(
        Ether(src=SRC_MAC, dst=DST_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="PA",
            seq=c_seq,
            ack=s_seq,
        )
        / Raw(load=client_data)
    )
    c_seq += len(client_data)
    if server_data is not None:
        pkts.append(
            Ether(src=DST_MAC, dst=SRC_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP)
            / TCP(
                sport=SERVER_PORT,
                dport=CLIENT_PORT,
                flags="PA",
                seq=s_seq,
                ack=c_seq,
            )
            / Raw(load=server_data)
        )
        s_seq += len(server_data)

wrpcap("mqtt-log-limits.pcap", pkts)
total = sum(len(p[Raw].load) for p in pkts if Raw in p)
print(f"wrote mqtt-log-limits.pcap: {len(pkts)} frames, {total} tcp-payload bytes")
