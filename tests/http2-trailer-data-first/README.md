# http2-trailer-data-first

HTTP/2 does not require HEADERS before DATA, so a stream may open with a DATA frame.

The trailer classifier must not read the first HEADERS block of such a stream as trailers:
it needs a completed header section and body data behind it. The opening fields must stay in
the header buffers, so both rules here match.

pcap from make-pcap.py, decoded by tshark as HTTP/2 with no tcp.analysis flags.
