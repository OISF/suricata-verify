# HTTP/1 header block that ends only because the capture ends

The request headers never see a blank line and the flow is never closed by a FIN; the last byte
is simply the last byte of the file. Stream teardown at end of file is what completes the block,
and it has to be visible to the raw buffer: on the branch that is the closure arm of the header
state, on main the buffer was always handed over as-is.

Run `python3 make-pcap.py` to regenerate `input.pcap`.
