# HTTP/1 chunked request whose trailer block is never terminated

The last chunk opens the trailer section, three fields follow with no blank line, then the
client closes the stream. Trailers are only reachable through their own buffers, so this pins
that block completion by closure fills them like any other block-shaped buffer.

The second flow sends the same traffic with a terminated trailer block, so the ordinary path
is covered in the same run.

Needs the trailer buffers, so it is expected to fail before the engine side lands.

Run `python3 make-pcap.py` to regenerate `input.pcap`.
