import sys

from scapy.all import Ether, ICMP, IP, Raw, TCP, wrpcap

out_dir = sys.argv[1]
C, S, R = "10.0.0.1", "10.0.0.2", "10.0.0.254"
cp, sp = 49152, 135
ci, si = 1000, 5000
call_id = 0x11223344


def pdu(ptype, body):
    hdr = b"\x05\x00" + bytes([ptype]) + b"\x03" + b"\x10\x00\x00\x00"
    hdr += (16 + len(body)).to_bytes(2, "little") + b"\x00\x00"
    hdr += call_id.to_bytes(4, "little")
    return hdr + body


req = pdu(0x00, b"\x00\x00\x00\x00" b"\x00\x00" b"\x00\x00" b"stub")
resp = pdu(0x02, b"\x00\x00\x00\x00" b"\x00\x00\x00\x00" b"stub")


def eth(src, dst):
    return Ether(src=src, dst=dst)


def pkt(src, dst, sport, dport, flags, seq, ack, payload=b""):
    p = eth("02:00:00:00:00:01", "02:00:00:00:00:02")
    p /= IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack
    )
    if payload:
        p /= Raw(payload)
    return p


pk = [
    pkt(C, S, cp, sp, "S", ci, 0),
    pkt(S, C, sp, cp, "SA", si, ci + 1),
    pkt(C, S, cp, sp, "A", ci + 1, si + 1),
    pkt(C, S, cp, sp, "PA", ci + 1, si + 1, req),
    pkt(S, C, sp, cp, "PA", si + 1, ci + 1 + len(req), resp),
]
# ICMP port unreachable from a router, embedding the client's request.
# The to-client inspect id is still 0 here: the response is handed to the
# parser on the client's ACK below.
inner = IP(src=C, dst=S) / TCP(sport=cp, dport=sp, flags="PA", seq=ci + 1,
                               ack=si + 1) / Raw(req)
pk.append(eth("02:00:00:00:00:03", "02:00:00:00:00:01")
          / IP(src=R, dst=C) / ICMP(type=3, code=3) / inner)
# client ACK: hands the response to the parser (parsed on opposing update)
pk.append(pkt(C, S, cp, sp, "A", ci + 1 + len(req), si + 1 + len(resp)))

wrpcap(f"{out_dir}/input.pcap", pk)
