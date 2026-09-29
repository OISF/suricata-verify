#!/usr/bin/env python3
# Generate a pcap where both SSH banners parse and the server (to-client)
# direction then sends a record header with pkt_len = 0: an invalid record
# (the header parser requires pkt_len > 1). The direction fails
# unrecoverably (invalid_record) and is logged with server.error; the
# client direction stays in the kex phase without failure.
#
# The client sends no ACK after the server banner. The ssh object is
# logged at the failure (the eve ssh log condition is failure-only -
# the handshake does not consume the one-shot tx log), so the error
# field is in the emitted ssh object. The ACK-ed normal-flow variant
# lives in tests/ssh-eve-invalid-record-ack.

from scapy.all import Ether, IP, TCP, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
SPORT = 49000
DPORT = 22
ETH_C2S = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ETH_S2C = Ether(src="00:00:00:00:00:00:02", dst="00:00:00:00:00:01")


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

    # invalid record: pkt_len 0 fails the header parser's pkt_len > 1 bound
    bad_rec = b"\x00\x00\x00\x00\x00\x00"
    pkts.append(packet(SERVER, DPORT, CLIENT, SPORT, sseq, cseq, bad_rec))

    wrpcap("input.pcap", pkts)
    print(f"wrote input.pcap ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
