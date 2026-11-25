# TLS handshake log limits

A ClientHello with 300 cipher suites and 300 extensions. The logger caps
each handshake array at 256 entries and sets `ciphers_truncated` and
`exts_truncated`.

`generate_pcap.py` is deterministic; `tls.pcap` is the committed output.
