# Test Description

This test demonstrates that if the stream reassembly depth is reached on one direction,
it does not block the other side.
For the given PCAP, to server direction reaches the depth and stops processing leading
to no alert having been logged for a valid to server request in the stream which would
be processed in case there was no depth (sid: 2).
However, this does not stall the packets in other direction from being the processed,
the response to the same request is still processed and a corresponding alert is logged
(sid: 1).

## PCAP

tshark.dev

## Related issues

https://redmine.openinfosecfoundation.org/issues/7044
