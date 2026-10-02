#!/usr/bin/env python3
# Generate a pcap where both SSH banners parse, a stateful drop rule then
# matches the server banner (the flow action is set after readiness was
# reached), and the server sends a record header with pkt_len = 0 afterwards:
# an invalid record (the header parser requires pkt_len > 1). In IDS mode the
# drop does not stop parsing, so the failure must still be logged - the drop
# must not consume the one-shot tx log with the success record.
#
# The client ACK that releases the server banner for inspection is also what
# makes the drop rule fire, so the drop is set before the invalid record is
# parsed.
#
# Run from the test directory: the pcap is written to input.pcap.

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 49000
DPORT = 22
ETH_C2S = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ETH_S2C = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")

CLIENT_BANNER = b"SSH-2.0-TestClient_1.0\r\n"
SERVER_BANNER = b"SSH-2.0-TestServer_1.0\r\n"
CLIENT_DATA = b"\x00\x00\x00\x14\x05\x14" + bytes(range(16))
BAD_RECORD = b"\x00\x00\x00\x00\x00\x00"


def packet(src, sport, dst, dport, seq, ack, payload, flags="PA"):
    p = Ether(src=ETH_C2S.src if src == CLIENT else ETH_S2C.src,
              dst=ETH_C2S.dst if src == CLIENT else ETH_S2C.dst) / \
        IP(src=src, dst=dst) / \
        TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    if payload:
        p = p / Raw(payload)
    return p


def main():
    cseq, sseq = 1000, 2000
    pkts = [
        packet(CLIENT, SPORT, SERVER, DPORT, cseq, 0, b"", flags="S"),
    ]
    cseq += 1
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, b"", flags="SA"))
    sseq += 1
    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, b"", flags="A"))

    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, CLIENT_BANNER))
    cseq += len(CLIENT_BANNER)
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, b"", flags="A"))

    # releases the client banner for inspection
    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, CLIENT_DATA))
    cseq += len(CLIENT_DATA)

    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, SERVER_BANNER))
    sseq += len(SERVER_BANNER)

    # releases the server banner for inspection: both banners are parsed here
    # and the drop rule matches, so the flow action is set after readiness
    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, b"", flags="A"))

    # invalid record: pkt_len 0 fails the header parser's pkt_len > 1 bound
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, BAD_RECORD))
    sseq += len(BAD_RECORD)

    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, b"", flags="FA"))

    wrpcap("input.pcap", pkts)
    print(f"wrote input.pcap ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
