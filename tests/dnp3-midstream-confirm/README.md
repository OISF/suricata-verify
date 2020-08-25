# Description

1. Test DNP3 parser against packet that may be created by malfunction device
2. Test DNP3 probing parser direction when starting midstream

# PCAP

The pcap is a simple packet DNP3 confirm (answer from server)
Packet is taken from real correct communication but it is patched
to simulate behavior of malfunction device:
- TCP source and destination ports are swapped
- DNP3 data link header DIR flag is reversed.
