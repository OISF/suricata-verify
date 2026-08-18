#!/usr/bin/env python3
# Regenerates input.pcap for the MQTT v5 unknown-property regression test.
#
# A single MQTT v5 CONNECT whose property block is a run of 0x7F bytes (unknown
# property identifier 127). parse_properties() must DROP unknown properties:
# each 0x7F would otherwise become one MQTTProperty::UNKNOWN Vec entry, growing
# the retained Vec unboundedly.
#
# 300 unknown properties are sent (> the MQTT_MAX_PROPERTIES cap of 256) so that,
# IF unknown-property retention regressed, 256 would be stored and the
# too_many_properties event would fire -- the test asserts that event count is 0,
# which only holds while unknown properties are being dropped.
from scapy.all import IP, TCP, Ether, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 49152
DPORT = 1883

NPROPS = 300  # > MQTT_MAX_PROPERTIES (256)


def mqtt_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


# properties block: NPROPS x 0x7F (unknown property identifier 127, no payload)
props = b"\x7f" * NPROPS
proplen = mqtt_varint(len(props))

var_header = (
    b"\x00\x04MQTT"   # protocol name len=4, "MQTT"
    b"\x05"            # protocol version 5 (enables property parsing)
    b"\x02"            # connect flags: clean session only
    b"\x00\x3c"        # keepalive = 60
    + proplen
    + props
)
payload = b"\x00\x00"  # client id length = 0
body = var_header + payload
connect = b"\x10" + mqtt_varint(len(body)) + body

pkts = []
cseq = 1000
sseq = 5000
pkts.append(IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=DPORT, flags="S", seq=cseq)); cseq += 1
pkts.append(IP(src=SERVER, dst=CLIENT) / TCP(sport=DPORT, dport=SPORT, flags="SA", seq=sseq, ack=cseq)); sseq += 1
pkts.append(IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq, ack=sseq))
pkts.append(IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=DPORT, flags="PA", seq=cseq, ack=sseq) / connect); cseq += len(connect)
pkts.append(IP(src=SERVER, dst=CLIENT) / TCP(sport=DPORT, dport=SPORT, flags="A", seq=sseq, ack=cseq))
pkts.append(IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=DPORT, flags="FA", seq=cseq, ack=sseq)); cseq += 1
pkts.append(IP(src=SERVER, dst=CLIENT) / TCP(sport=DPORT, dport=SPORT, flags="FA", seq=sseq, ack=cseq)); sseq += 1
pkts.append(IP(src=CLIENT, dst=SERVER) / TCP(sport=SPORT, dport=DPORT, flags="A", seq=cseq, ack=sseq))

wrpcap("input.pcap", [Ether() / p for p in pkts])
