Chunked request whose trailer section reuses names from the header section.

The trailer fields (`Server-Timing`, `User-Agent`, `Host`) must be reachable through
`http.trailer`, `http.trailer.raw` and `http.trailer_names`, and must not be reachable through
`http.header`, `http.header.raw`, `http.header_names` or `http.user_agent`. Before the trailer
buffers existed, matching them was left to packet timing and a trailer named `User-Agent`
silently extended the user agent value.

Crafted with `make-pcap.py` (no arguments).
