# http2-trailer-repeats

A trailer block that repeats one field through the HPACK dynamic table: a
literal-with-indexing `server-timing: dur=2` inserts the pair at index 62, and
the one-byte reference `0xbe` sends it again. tshark decodes two `server-timing`
fields from the block.

Both occurrences must reach `http.trailer` (one line per entry), `http.trailer_names`
and the `http.request_trailers` array. Before the fix the second one was dropped,
because the buffers skipped a block whose name and value came from the same
dynamic-table entry.

`make-pcap.py` generates the capture: request header block at #4, the repeat
trailer block at #8.
