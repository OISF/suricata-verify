#!/usr/bin/env python3
from scapy.all import Ether, IP, TCP, Raw, wrpcap

CM, SM = "02:00:00:00:00:02", "02:00:00:00:00:01"

def ftp_control(client, server, client_port, passive_port, cisn, sisn):
    def packet(to_server, flags, seq, ack=0, payload=b""):
        if to_server:
            base = Ether(src=CM, dst=SM) / IP(src=client, dst=server) / TCP(sport=client_port, dport=21, flags=flags, seq=seq, ack=ack)
        else:
            base = Ether(src=SM, dst=CM) / IP(src=server, dst=client) / TCP(sport=21, dport=client_port, flags=flags, seq=seq, ack=ack)
        return base / Raw(payload) if payload else base

    packets = [
        packet(True, "S", cisn),
        packet(False, "SA", sisn, cisn + 1),
        packet(True, "A", cisn + 1, sisn + 1),
    ]
    cs, ss = cisn + 1, sisn + 1

    def client_line(data):
        nonlocal cs
        packets.append(packet(True, "PA", cs, ss, data))
        cs += len(data)

    def server_line(data):
        nonlocal ss
        packets.append(packet(False, "PA", ss, cs, data))
        ss += len(data)

    p1, p2 = divmod(passive_port, 256)
    server_line(b"220 FTP ready\r\n")
    client_line(b"USER anonymous\r\n")
    server_line(b"331 User name okay\r\n")
    client_line(b"PASV\r\n")
    server_line(b"227 Entering Passive Mode (10,0,0,1,%d,%d)\r\n" % (p1, p2))
    client_line(b"RETR a\r\n")
    return packets

# The first flow creates a successful expectation, keeping expectation_count
# non-zero. GDB injects failure into the second flow's ExpectationList.
packets = ftp_control("10.0.1.2", "10.0.1.1", 40000, 51211, 1000, 2000)
packets += ftp_control("10.0.0.2", "10.0.0.1", 50000, 51210, 3000, 4000)

# App-layer detection on this data flow consults the failed flow's IP pair.
def data_packet(to_server, flags, seq, ack=0, payload=b""):
    if to_server:
        base = Ether(src=CM, dst=SM) / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=50001, dport=51210, flags=flags, seq=seq, ack=ack)
    else:
        base = Ether(src=SM, dst=CM) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51210, dport=50001, flags=flags, seq=seq, ack=ack)
    return base / Raw(payload) if payload else base

packets += [
    data_packet(True, "S", 5000),
    data_packet(False, "SA", 6000, 5001),
    data_packet(True, "A", 5001, 6001),
    data_packet(True, "PA", 5001, 6001, b"DATA"),
]
for i, p in enumerate(packets):
    p.time = 1.0 + i / 1000000.0
wrpcap("input.pcap", packets)
