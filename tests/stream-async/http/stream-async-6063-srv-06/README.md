# Test

Cover branch case where the engine receives a FIN packet, without payload,
as the first packet seen in a stream, with no packet from the other side of the flow.

## Pcap

Extracted from pcap from test http-all-headers pcap, selecting the server-side of the flow, from the packet with the server's FIN onwards, then editting the HEX to un-set the ACK flag.

## Related to

https://redmine.openinfosecfoundation.org/issues/8339
