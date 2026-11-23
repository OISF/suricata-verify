# Description

An ICMPv4 port-unreachable error from a router matches a DCERPC-over-TCP
flow (by its embedded datagram) and is attached to it. Detection skips the
app-layer tx walk for the error, but a rule alerts on it. With
`detect.guess-applayer-tx` enabled, the alert attaches the flow's only live
transaction, and the EVE alert logger adds the dcerpc metadata.

The DCERPC record builder must be selected by the flow's proto: the packet
proto is ICMP, and the UDP builder expects an activity UUID that TCP
transactions never set, which aborted the engine.

The test checks the alert record at the error (packet 6): guessed tx 0,
dcerpc request present and the response still unreplied. The response is
handed to the parser by the client's ACK (packet 7), where the tx record is
logged with the TCP builder. Before the fix the run aborts at the alert and
the test fails.

# PCAP

Crafted with scapy (`craft.py`, run as `craft.py <outdir>`). A DCERPC/TCP
request and response, then an ICMP port-unreachable from a router embedding
the client request. The client's ACK of the response follows: it is what
hands the response to the parser, so the error (packet 6) lands while the
to-client inspect id is still 0.
