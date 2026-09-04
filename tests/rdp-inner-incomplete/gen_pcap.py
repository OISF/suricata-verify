#!/usr/bin/env python3
"""
Generate rdp-inner-incomplete.pcap

A client opens a TCP connection to an RDP server on port 3389 and sends,
as its first payload, a *complete* T.123 TPKT (03 00 00 07 02 f0 80) whose
inner X.223 class 0 data PDU has an empty payload, followed by a second
complete TPKT whose inner CS_CORE block claims 255 bytes inside a
4-byte container. Both TPKTs are fully present on the wire, but their
inner content makes the RDP sub-parsers report "Incomplete", which before
the fix escaped parse_t123_tpkt and made the app-layer parser request
more bytes forever without consuming anything, wedging RDP decoding for
the to-server direction.

The pcap then continues with a real RDP handshake (X.224 CR/CC, MCS
Connect-Request/Response; payloads taken from rdp-protocol/RDP-003.pcap).
A working parser must consume the poisoned TPKT as an unknown payload and
still log the rest of the handshake; a wedged parser only logs the
to-client direction.
"""

from scapy.all import Ether, IP, TCP, wrpcap

SRC_IP, SRC_PORT = "10.0.0.1", 49152
DST_IP, DST_PORT = "10.0.0.2", 3389
C_ISN, S_ISN = 1000, 5000

# complete TPKT (len 7): X.223 data class 0 header, empty payload
TPKT_POISON1 = bytes.fromhex("0300000702f080")

# complete TPKT (len 18): X.223 data, MCS connect request whose inner
# CS_CORE block claims 255 bytes inside a 4-byte container
TPKT_POISON2 = bytes.fromhex("0300001202f0807f6544756361 0401c0ff00".replace(" ", ""))

# X.224 connection request, cookie mstshash:A70067
TPKT_X224_CR = bytes.fromhex(
    "030000241fe00000"
    "000000436f6f6b69"
    "653a206d73747368"
    "6173683d41373030"
    "36370d0a"
)

# X.224 connection confirm
TPKT_X224_CC = bytes.fromhex(
    "0300000b06d00000"
    "123400"
)

# MCS connect request (X.223 data): ClientData core + net blocks
TPKT_MCS_CR = bytes.fromhex(
    "0300019c02f0807f"
    "6582019004010104"
    "01010101ff301902"
    "0122020102020100"
    "0201010201000201"
    "010202ffff020102"
    "3019020101020101"
    "0201010201010201"
    "0002010102020420"
    "020102301c0202ff"
    "ff0202fc170202ff"
    "ff02010102010002"
    "01010202ffff0201"
    "020482012f000500"
    "147c000181260008"
    "00100001c0004475"
    "6361811801c0d400"
    "0400080080046003"
    "01ca03aa09040000"
    "280a000049005300"
    "440032002d004b00"
    "4d00380034003100"
    "3700380000000000"
    "0000000004000000"
    "000000000c000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "01ca010000000000"
    "0f00070001003500"
    "3500320037003400"
    "2d004f0045004d00"
    "2d00300030003100"
    "3100390030003300"
    "2d00300030003100"
    "3000370000000000"
    "0000000000000000"
    "0000000000000000"
    "04c00c0009000000"
    "0000000002c00c00"
    "0b00000000000000"
    "03c02c0003000000"
    "7264706472000000"
    "00008080636c6970"
    "726472000000a0c0"
    "726470736e640000"
    "000000c0"
)

# MCS connect response (X.223 data): ServerData
TPKT_MCS_CC = bytes.fromhex(
    "0300014d02f0807f"
    "668201410a010002"
    "0100301a02012202"
    "0103020100020101"
    "0201000201010203"
    "00fff80201020482"
    "011b000500147c00"
    "012a14760a010100"
    "01c0004d63446e81"
    "04010c0800040008"
    "00030c1000eb0303"
    "00ec03ed03ee0300"
    "00020cec00080000"
    "0002000000200000"
    "00b8000000778e84"
    "ed14edf1083d3612"
    "84c28dcd52da7230"
    "1be1dc7fdf62accd"
    "22660b3372010000"
    "0001000000010000"
    "0006005c00525341"
    "3148000000000200"
    "003f000000010001"
    "0083f6d4ca7c0597"
    "5a72cb0b5ca0ece5"
    "9d468470e83ac058"
    "9091a00c9119bcab"
    "88efc96b261a6290"
    "e8a9385b5aa4198f"
    "5f29caa6c62c9143"
    "9003bda0a2e9b8a6"
    "c900000000000000"
    "00080048001b0c72"
    "49c4782f8c7d4c9f"
    "c6182f3164c66099"
    "979fa4f292683db0"
    "67cfc711a7237512"
    "767a01199ca613be"
    "af0647dd0120a94e"
    "54066f6a61018e57"
    "e725ee0f3f000000"
    "0000000000"
)


def tcp(seq, ack, flags, payload, to_server=True):
    if to_server:
        ip, sp, dp = IP(src=SRC_IP, dst=DST_IP), SRC_PORT, DST_PORT
    else:
        ip, sp, dp = IP(src=DST_IP, dst=SRC_IP), DST_PORT, SRC_PORT
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / ip
        / TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
        / (payload if payload else b"")
    )


def main():
    t = 1700000000.0
    pkts = []

    def add(pkt, dt):
        nonlocal t
        t += dt
        pkt.time = t
        pkts.append(pkt)

    # 3-way handshake
    add(tcp(C_ISN, 0, "S", b""), 0.05)
    add(tcp(S_ISN, C_ISN + 1, "SA", b"", to_server=False), 0.05)
    add(tcp(C_ISN + 1, S_ISN + 1, "A", b""), 0.05)

    # poisoned TPKTs: complete on the wire, malformed inner payloads
    c_seq, s_seq = C_ISN + 1, S_ISN + 1
    for poison in (TPKT_POISON1, TPKT_POISON2):
        add(tcp(c_seq, s_seq, "PA", poison), 0.2)
        c_seq += len(poison)
        add(tcp(s_seq, c_seq, "A", b"", to_server=False), 0.05)

    # real handshake, to be logged even after the poisoned TPKT
    for payload in (TPKT_X224_CR, TPKT_X224_CC, TPKT_MCS_CR, TPKT_MCS_CC):
        if payload is TPKT_X224_CR or payload is TPKT_MCS_CR:
            # to-server
            add(tcp(c_seq, s_seq, "PA", payload), 0.2)
            c_seq += len(payload)
        else:
            # to-client, acking the latest client data
            add(tcp(s_seq, c_seq, "PA", payload, to_server=False), 0.2)
            s_seq += len(payload)

    # final ack
    add(tcp(c_seq, s_seq, "A", b""), 0.05)

    wrpcap("rdp-inner-incomplete.pcap", pkts)
    print("wrote rdp-inner-incomplete.pcap with %d packets" % len(pkts))


if __name__ == "__main__":
    main()
