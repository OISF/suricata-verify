Trailer fields that arrive in the CONTINUATION frame
====================================================

A trailer HEADERS frame may carry END_STREAM without END_HEADERS, in which case the block is
completed by CONTINUATION frames (RFC 9113 6.2, 8.1). This capture splits the trailer block of
one stream across exactly those two frames, in separate TCP segments: `grpc-message` rides the
HEADERS frame, `user-agent` and `server-timing` arrive in the CONTINUATION.

An implementation that treats END_STREAM as "header section done" would build the trailer buffers
from the first frame only, and the last two fields would never be inspected. All four assertions
must hold; sid 19 checks the buffers are not just matching anything.

The close-out logic is parameterised by direction, so the same holds for a server side trailer
block; the to_client case is covered by the trailer tests in `http2-trailer`.

Regenerate with `python3 make-pcap.py input.pcap`; `tshark -r input.pcap -Y http2` shows the
frame types and flags.
