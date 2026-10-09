Same traffic as `http1-trailer`, but the terminating `0\r\n` chunk ends one segment and the
trailer fields arrive in the next one, with an ACK in between.

That makes detection see the transaction in the trailer state while its fields are not parsed
yet. The trailer buffers are registered at that state, so a round there is not final and the
match still happens once the section completes.

Crafted with `make-pcap.py --split`.
