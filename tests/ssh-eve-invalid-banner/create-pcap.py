#!/usr/bin/env python3
# Generate a pcap where the client (to-server) direction sends an invalid
# SSH banner line: the direction fails unrecoverably (invalid_banner) and
# is logged in the eve ssh object with client.error; the server direction
# parses a valid banner and completes normally.

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 49000
DPORT = 22
ETH_C2S = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ETH_S2C = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")


def packet(src, sport, dst, dport, seq, ack, payload, flags="PA"):
    return (Ether(src=ETH_C2S.src if src == CLIENT else ETH_S2C.src,
                  dst=ETH_C2S.dst if src == CLIENT else ETH_S2C.dst) /
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) /
            Raw(payload))


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

    # invalid banner: a complete line that is not SSH-<proto>-<software>
    bad = b"NOT-AN-SSH-BANNER\r\n"
    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, bad))
    cseq += len(bad)
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, b"", flags="A"))

    # valid server banner: the server direction parses normally
    good = b"SSH-2.0-TestServer_1.0\r\n"
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, good))
    sseq += len(good)
    pkts.append(packet(CLIENT, SPORT, SERVER, DPORT, cseq, sseq, b"", flags="A"))

    wrpcap("input.pcap", pkts)
    print(f"wrote input.pcap ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
