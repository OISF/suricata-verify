#!/usr/bin/env python3
# Generates input.pcap and firewall.rules for
# ruletype-firewall-290-lte-mpm-host-ruleset.
#
# The operator's LTE structure (Redmine #9149 note 2): one broad tcp:all
# session rule plus N accept:flow http1:<request_headers rules, one per
# distinct host. Only one host appears in the traffic; its rule must accept
# the flows at request_headers, while the N-1 unmatched rules must stay out
# of the candidate list at the hook (the MPM is their only prefilter there).
#
# Three flows to 93.184.216.34:80:
#   flow A, B: the request line and the headers arrive in one packet (the
#   common case: first detect with the headers state and buffer available);
#   flow C: the request line is split over two packets, so the first detect
#   happens at request line (T < hook): the pending window - the rules are
#   candidates via the per-state entries, no default may fire at the line
#   state, and the rule resolves once the line and headers complete.
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SIP, DIP = "10.20.0.14", "93.184.216.34"  # $HOME_NET -> $EXTERNAL_NET
DP = 80
N = 500  # distinct host rules; sid 100..100+N-1, the matching one is 100+N


class Flow:
    def __init__(self, sport, cs, ss):
        self.sp = sport
        self.cseq, self.sseq = cs + 1, ss + 1
        self.sack, self.cake = cs + 1, ss + 1

    def mk(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        p = Ether(src="00:11:22:33:44:55" if src == SIP else "66:77:88:99:aa:bb",
                  dst="66:77:88:99:aa:bb" if src == SIP else "00:11:22:33:44:55") / \
            IP(src=src, dst=dst) / \
            TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags)
        if payload:
            p = p / Raw(payload)
        return p

    def hs(self, pkts):
        Cs, Ss = self.cseq - 1, self.sseq - 1
        pkts.append(self.mk(SIP, DIP, self.sp, DP, Cs, 0, "S"))
        pkts.append(self.mk(DIP, SIP, DP, self.sp, Ss, Cs + 1, "SA"))
        self.c(b"", "A", pkts)

    def c(self, payload, flags, pkts):
        pkts.append(self.mk(SIP, DIP, self.sp, DP, self.cseq, self.cake, flags, payload))
        self.cseq += len(payload) + (1 if "F" in flags else 0)
        self.sack = self.cseq

    def s(self, payload, flags, pkts):
        pkts.append(self.mk(DIP, SIP, DP, self.sp, self.sseq, self.sack, flags, payload))
        self.sseq += len(payload) + (1 if "F" in flags else 0)
        self.cake = self.sseq

    def resp(self, pkts):
        self.s(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "PA", pkts)
        self.c(b"", "A", pkts)

    def fin(self, pkts):
        self.s(b"", "F", pkts)
        self.c(b"", "A", pkts)
        self.c(b"", "F", pkts)
        self.s(b"", "A", pkts)

    def request_complete(self, pkts):
        self.c(b"GET /index HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "PA", pkts)
        self.s(b"", "A", pkts)


pkts = []

# flow A and B: common case, line and headers in one packet
for sport, cs, ss in ((49101, 2000, 6000), (49102, 4000, 8000)):
    f = Flow(sport, cs, ss)
    f.hs(pkts)
    f.request_complete(pkts)
    f.resp(pkts)
    f.fin(pkts)

# flow C: the request line is split over two packets
f = Flow(49103, 6000, 10000)
f.hs(pkts)
f.c(b"GET /ind", "PA", pkts)
f.s(b"", "A", pkts)
f.c(b"ex HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "PA", pkts)
f.s(b"", "A", pkts)
f.resp(pkts)
f.fin(pkts)

wrpcap("input.pcap", pkts)
print(f"wrote input.pcap: {len(pkts)} packets")

# rules: the broad session rule, N distinct host rules, the matching one and
# the opposite-direction scaffolding (so its defaults cannot drop the flow
# before this direction completes)
with open("firewall.rules", "w") as fp:
    fp.write("accept:hook tcp:all $HOME_NET any <> $EXTERNAL_NET any "
             "(tcp.session:setup,established; "
             "app-layer-protocol:unknown|http|tls|http2; sid:1; gid:10000047;)\n")
    for i in range(N):
        fp.write(f'accept:flow,alert http1:<request_headers $HOME_NET any -> $EXTERNAL_NET any '
                 f'(http.host; content:"host{i}.example{i}.com"; startswith; endswith; '
                 f'sid:{100 + i}; gid:10000047;)\n')
    fp.write(f'accept:flow,alert http1:<request_headers $HOME_NET any -> $EXTERNAL_NET any '
             f'(http.host; content:"www.example.com"; startswith; endswith; '
             f'sid:{100 + N}; gid:10000047;)\n')
    fp.write("accept:hook http1:<response_complete $EXTERNAL_NET any -> $HOME_NET any "
             "(sid:9001;)\n")
print(f"wrote firewall.rules: {N + 3} rules, matching sid {100 + N}")
