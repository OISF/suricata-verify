#!/usr/bin/env python3
# Generate a pcap of an SSH flow in which the server sends a banner
# line of 300+ bytes without EOL. The direction parses the line (it
# is published on the first parse, which fires the one-shot
# ssh.long_banner event) and stays parked in the banner state.

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 49000
DPORT = 22
ETH_C2S = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ETH_S2C = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")


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

    # long banner line, no EOL: 256 bytes or more keeps the direction
    # parked in the banner state and fires the long_banner event
    long_banner = b"SSH-2.0-" + b"A" * 300
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, long_banner))

    wrpcap("input.pcap", pkts)
    print(f"wrote input.pcap ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
