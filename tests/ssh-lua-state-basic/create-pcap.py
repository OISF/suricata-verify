#!/usr/bin/env python3
# Generate a pcap of a complete SSH session in both directions:
# both banners parse and both directions send a (valid) newkeys
# record, so every state hook (banner, kex, session) is reachable
# in both the request (to-server) and response (to-client)
# direction.
#
# The client sends no ACK after the last server data packet: the
# ssh transaction is then logged at flow end, after all data has
# been parsed, and the state hooks of both directions evaluate
# against the fully parsed session.

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 49000
DPORT = 22
ETH_C2S = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ETH_S2C = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")

NEWKEYS = b"\x00\x00\x00\x02\x00\x15"  # msg 21 (newkeys), no payload


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
        Ether(src=ETH_C2S.src, dst=ETH_C2S.dst) / IP(src=CLIENT, dst=SERVER) /
        TCP(sport=SPORT, dport=DPORT, seq=cseq, flags="S"),
    ]
    cseq += 1
    pkts.append(Ether(src=ETH_S2C.src, dst=ETH_S2C.dst) / IP(src=SERVER, dst=CLIENT) /
                TCP(sport=DPORT, dport=SPORT, seq=sseq, ack=cseq, flags="SA"))
    sseq += 1
    pkts.append(Ether(src=ETH_C2S.src, dst=ETH_C2S.dst) / IP(src=CLIENT, dst=SERVER) /
                TCP(sport=SPORT, dport=DPORT, seq=cseq, ack=sseq, flags="A"))

    cli_banner = b"SSH-2.0-TestClient_1.0\r\n"
    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, cli_banner))
    cseq += len(cli_banner)

    srv_banner = b"SSH-2.0-TestServer_1.0\r\n"
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, srv_banner))
    sseq += len(srv_banner)

    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, NEWKEYS))
    cseq += len(NEWKEYS)

    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, NEWKEYS))
    sseq += len(NEWKEYS)

    wrpcap("input.pcap", pkts)
    print(f"wrote input.pcap ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
