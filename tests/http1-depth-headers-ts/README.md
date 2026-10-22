# HTTP/1 header block cut by stream reassembly depth

`stream.reassembly.depth` is lowered to 2000 so reassembly stops inside the request header
block: no state hook and no closure can complete it from a hook. The peer acknowledges every
segment, so htp does hold the bytes up to the cut - without those ACKs `AdjustToAcked` keeps
unacked data away from the app-layer and the test would prove nothing.

This is the shape where the completion gate has to open: a block that cannot advance any
further must be inspected, which is what main does for it. `http.uri` and a bare `content` on
the same bytes are the positive controls showing that a detection round really runs for the
transaction. Flow B is a complete transaction in the same capture.

Run `python3 make-pcap.py` to regenerate `input.pcap`.
