# Description

An ICMPv4 error is sent to the source of the datagram that caused it, so the
embedded datagram's source is the error's destination. Errors where that does
not hold are not about the embedded datagram and must not be matched to its
flow.

The pcap is an HTTP flow with two ICMPv4 destination-unreachable errors after
the handshake, both embedding the client's SYN:

- packet 4, `10.0.0.254 -> 10.0.0.1`: sent to the SYN's source. It is matched
  to the flow (to_client), as before.
- packet 5, `1.2.3.4 -> 5.6.7.8`: sent between two unrelated hosts. It sets
  `decoder.event.icmpv4.ipv4_emb_addr_mismatch` and is no longer matched to the
  flow, so the flow counts 5 packets to the client, not 6.

# PCAP

Crafted with scapy (`craft.py <out.pcap>`).
