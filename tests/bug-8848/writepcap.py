#!/usr/bin/env python
#
# Two FTP control flows.
#
# The first sends commands padded with trailing spaces. Each padded command
# makes the parser allocate the full line and account it against the FTP
# memcap; only the stripped length is given back when the transaction is
# freed, so the padding leaks from the memuse counter.
#
# The second flow is an ordinary session that arrives after the padded one.
# Once the counter is past the memcap, allocating its state fails and the flow
# is never parsed.

from scapy.all import *

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"

PADDING = 1000
COMMANDS = 30


class Session:
    """A TCP session with sequence numbers tracked for both directions."""

    def __init__(self, sport):
        self.sport = sport
        self.cseq = 1000
        self.sseq = 2000
        self.pkts = []

        self.pkts.append(self.to_server("S"))
        self.cseq += 1
        self.pkts.append(self.to_client("SA"))
        self.sseq += 1
        self.pkts.append(self.to_server("A"))

    def to_server(self, flags, payload=b""):
        return (
            Ether()
            / IP(src=CLIENT, dst=SERVER)
            / TCP(sport=self.sport, dport=21, flags=flags, seq=self.cseq, ack=self.sseq)
            / Raw(payload)
        )

    def to_client(self, flags, payload=b""):
        return (
            Ether()
            / IP(src=SERVER, dst=CLIENT)
            / TCP(sport=21, dport=self.sport, flags=flags, seq=self.sseq, ack=self.cseq)
            / Raw(payload)
        )

    def request(self, payload):
        self.pkts.append(self.to_server("PA", payload))
        self.cseq += len(payload)

    def response(self, payload):
        self.pkts.append(self.to_client("PA", payload))
        self.sseq += len(payload)


padded = Session(40000)
padded.response(b"220 ready\r\n")
for _ in range(COMMANDS):
    padded.request(b"USER a" + b" " * PADDING + b"\r\n")
    padded.response(b"331 password\r\n")

ordinary = Session(40001)
ordinary.response(b"220 ready\r\n")
ordinary.request(b"USER bob\r\n")
ordinary.response(b"331 password\r\n")
ordinary.request(b"QUIT\r\n")
ordinary.response(b"221 bye\r\n")

wrpcap("input.pcap", padded.pkts + ordinary.pkts)
