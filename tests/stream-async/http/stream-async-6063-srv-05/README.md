# Test

Cover branch case where the engine receives a FIN packet, without payload,
as the first packet seen in a stream, with no packet from the other side of the flow.

## Pcap

Extracted from pcap from test http-request-header pcap, selecting the server-side of the flow, from the packet with the server's FIN onwards.
The `ACK` flag was removed by editting the pcap hex.

## Related to

https://redmine.openinfosecfoundation.org/issues/8339
