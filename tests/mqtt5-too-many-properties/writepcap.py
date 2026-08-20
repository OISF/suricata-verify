#!/usr/bin/env python3
# Regenerates input.pcap for the MQTT v5 too_many_properties event test.
#
# A single MQTT v5 CONNECT whose property block contains many USER_PROPERTY
# entries (id 0x26), each with a unique key. parse_properties() caps the stored
# Vec<MQTTProperty> at MQTT_MAX_PROPERTIES (256); once a CONNECT reaches that many
# stored properties the parser raises the too_many_properties event.
#
# USER_PROPERTY is the property MQTT v5 explicitly allows to repeat, so it is the
# realistic way to reach the cap. Unique keys are used so the eve logger emits
# distinct JSON keys (it logs each user property as key->value), keeping the mqtt
# record valid JSON. UNKNOWN properties are dropped and would NOT count toward
# the cap, so a known property id is required.
from scapy.all import IP, TCP, Ether, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 49152
DPORT = 1883

NPROPS = 300  # > MQTT_MAX_PROPERTIES (256) so the cap/event definitely trigger


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


def mqtt_str(s):
    b = s.encode()
    return len(b).to_bytes(2, "big") + b


# properties block: NPROPS x USER_PROPERTY(key=unique, value="")
props = b"".join(b"\x26" + mqtt_str(f"k{i}") + mqtt_str("") for i in range(NPROPS))
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
