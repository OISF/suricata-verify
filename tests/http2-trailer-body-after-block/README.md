# http2-trailer-body-after-block

A trailer block that does not end the stream, with body data behind it.

RFC 9113 section 8.1 requires the header block that carries trailers to end the stream. A
lenient peer can still send one without `END_STREAM` and then more `DATA`. The direction
stays at the body state for such a block, so everything behind it is still body data.

The case covers the sequence end to end: the body frame before the block, the body frame
behind it and the trailer field itself are asserted separately, so a regression tells which
of the three was lost. The progress contract itself - a trailer block only moves the
direction when the block ends the stream, including when it is split over HEADERS and
CONTINUATION - is pinned by the unit tests in `rust/src/http2/http2.rs`, which is where the
old behaviour was observable.

`make-pcap.py` generates the capture.
