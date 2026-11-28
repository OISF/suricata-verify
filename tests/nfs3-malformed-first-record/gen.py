"""Generate input.pcap: a malformed NFSv3 record as the first of its flow.

The WRITE arguments stop after the file handle, so the parser cannot read the
offset/count/data. The anomaly has to be raised even though no transaction
exists yet: with a state-level event the first record of a flow reported
nothing, and a pipelined reply flagged whatever transaction was newest.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nfs_sv_common import Pcap, be32, v3_call, v3_fh

SRC, SRV = "192.168.1.10", "192.168.1.20"
FH3 = v3_fh(0x42)


def flow(p, client_port, steps):
    cli, srv = (SRC, client_port), (SRV, 2049)
    p.tcp(cli, srv, syn=True)
    p.tcp(srv, cli, synack=True)
    for d, payload in steps:
        if d == "c":
            p.tcp(cli, srv, payload=payload)
        else:
            p.tcp(srv, cli, payload=payload)
            p.tcp(cli, srv, pure_ack=True)


def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "input.pcap")
    p = Pcap(out)
    # flow A: malformed WRITE as the very first record of the flow
    flow(p, 941, [("c", v3_call(1, 7, FH3))])
    # flow B: a valid LOOKUP first, then the malformed WRITE, so the anomaly
    # must land on the malformed record and not on the newest transaction
    flow(p, 942, [("c", v3_call(2, 3, FH3 + be32(5) + b"cfile" + b"\x00" * 3)),
                  ("c", v3_call(3, 7, FH3))])
    p.close()


if __name__ == "__main__":
    main()
