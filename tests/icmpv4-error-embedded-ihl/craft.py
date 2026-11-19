import sys

from scapy.all import Ether, ICMP, IP, Raw, TCP, raw, wrpcap

out_dir = sys.argv[1]
C1, C2, S, R = "10.0.0.1", "10.0.0.3", "10.0.0.2", "10.0.0.254"
CP1, SP1 = 37892, 135
CP2, SP2 = 40000, 80
CI, SI = 1000, 5000


def eth(src, dst):
    return Ether(src=src, dst=dst)


def tcp(src, dst, sport, dport, flags, seq, ack):
    return eth("02:00:00:00:00:01", "02:00:00:00:00:02") / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack
    )


def handshake(c, cp, sp):
    return [
        tcp(c, S, cp, sp, "S", CI, 0),
        tcp(S, c, sp, cp, "SA", SI, CI + 1),
        tcp(c, S, cp, sp, "A", CI + 1, SI + 1),
    ]


def unreach(c, port, options, sport, dport):
    inner = (IP(src=c, dst=S, options=options, proto=6)
             / TCP(sport=sport, dport=dport, flags="PA", seq=CI + 1, ack=SI + 1)
             / Raw(b"\x00" * 8))
    return (eth("02:00:00:00:00:03", "02:00:00:00:00:01")
            / IP(src=R, dst=c) / ICMP(type=3, code=3) / raw(inner))


# Router Alert option: bytes 94 04 <value>. The "ports" read at fixed
# offset 20 are 0x9404=37892 and the 2-byte value.
pk = handshake(C1, CP1, SP1) + handshake(C2, CP2, SP2)
# flow 1: option value encodes flow 1's ports; real TCP header has other ports
pk.append(unreach(C1, CP1, b"\x94\x04\x00\x87", 12345, 54321))
# flow 2: option value does not encode flow 2's ports; real TCP header does
pk.append(unreach(C2, CP2, b"\x94\x04\x00\x01", CP2, SP2))

for i, p in enumerate(pk):
    p.time = 1700000000 + i * 0.001
wrpcap(f"{out_dir}/input.pcap", pk)
