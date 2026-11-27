# http2-trailer-amp

A trailer block of 16010 bytes: one literal-with-indexing `x-amp: <4000 x 'A'>`
(dynamic table index 62) followed by 12000 one-byte references to it, i.e. 12001
field lines in a frame that has to fit 16384 bytes.

This is the amplification case the trailer logging bound exists for. Logging
every field once made the engine print "Formatted JSON EVE record too large, will
be dropped" for the alert, fileinfo and http records, so appending a trailer
block to a stream made its EVE alerts disappear. The test asserts the `http`
event is still written and that `request_trailers` is bounded instead of listing
all 12001 entries.

`make-pcap.py` generates the capture: request header block at #4, the amplified
trailer block at #8. tshark reads the frame as a trailer block and decodes until
its own decompression limit (260 KB), which this block exceeds; Suricata's parser
decodes every reference, which is the point.
