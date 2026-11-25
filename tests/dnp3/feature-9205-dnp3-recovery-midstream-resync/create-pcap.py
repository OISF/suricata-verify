#!/usr/bin/env python3

from scapy.all import Ether, IP, Raw, TCP, wrpcap

OUT = "input.pcap"

# Frames from feature-9205-dnp3-recovery-default.
VALID_REQUEST = bytes.fromhex("05640844010002004d6cc0c0016da0")
VALID_RESPONSE = bytes.fromhex("05640a43030004006e47c0c08100009ce8")
GARBAGE = bytes.fromhex("deadbeef0011")


def main():
    # A connection picked up mid-stream: the first packet seen comes from the
    # outstation (port 20000) and starts mid-frame, so the start sequence of the
    # response it carries is not at offset 0.
    master, outstation = "10.0.7.1", "10.0.7.2"
    mport, oport = 10008, 20000
    m2o = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src=master, dst=outstation)
    o2m = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01") / IP(src=outstation, dst=master)
    mseq, oseq = 1000, 2000
    first = GARBAGE + VALID_RESPONSE
    packets = [
        o2m / TCP(sport=oport, dport=mport, seq=oseq, ack=mseq, flags="PA") / Raw(first),
        m2o / TCP(sport=mport, dport=oport, seq=mseq, ack=oseq + len(first), flags="A"),
    ]
    oseq += len(first)
    packets += [
        m2o / TCP(sport=mport, dport=oport, seq=mseq, ack=oseq, flags="PA") / Raw(VALID_REQUEST),
        o2m / TCP(sport=oport, dport=mport, seq=oseq, ack=mseq + len(VALID_REQUEST), flags="A"),
    ]
    mseq += len(VALID_REQUEST)
    packets += [
        o2m / TCP(sport=oport, dport=mport, seq=oseq, ack=mseq, flags="PA") / Raw(VALID_RESPONSE),
        m2o / TCP(sport=mport, dport=oport, seq=mseq, ack=oseq + len(VALID_RESPONSE), flags="A"),
    ]
    for offset, packet in enumerate(packets):
        packet.time = 1 + offset
    wrpcap(OUT, packets)


if __name__ == "__main__":
    main()
