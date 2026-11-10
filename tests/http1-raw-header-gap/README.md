# HTTP/1 header block with a lost segment, closed by FIN

One segment is missing from the middle of an unterminated header block (a real sequence gap,
so the direction carries STREAM_GAP rather than STREAM_DEPTH), then the client closes.
Closure is enough for htp to finish the block, so the raw buffer, the normalized buffer and
the single-field keyword all see it.

This is the disrupted-stream case next to `http1-raw-header-stream-depth`: a gap does not take
the direction out of inspection the way the depth limit does.

Run `python3 make-pcap.py` to regenerate `input.pcap`.
