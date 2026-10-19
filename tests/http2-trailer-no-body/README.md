HTTP/2 trailer blocks that follow a message with no DATA frames. RFC 9113 lets a
stream close with a HEADERS block, so classification keys on block sequence rather than
on body data. Regenerate with `python3 make-pcap.py`; tshark parses it as HTTP/2 with
no tcp.analysis flags.
