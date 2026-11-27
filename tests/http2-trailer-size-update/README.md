# http2-trailer-size-update

A trailer block whose only content is `0x20`, a dynamic table size update to
zero. It is a valid header block with no field in it, and tshark decodes it as a
header block fragment with no header.

The trailer buffers must stay empty: before the fix every block was serialized as
a field, so `http.trailer` returned `": \r\n"` and `http.trailer_names` returned
three CRLFs, and content or size matches could fire on a section that holds no
field. `http.request_trailers` still records the size update as
`{"table_size_update": 0}`.

`make-pcap.py` generates the capture: request header block at #4, the size-update
trailer block at #8.
