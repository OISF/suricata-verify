Tests the buffering configuration required to match certificate fields on
larger files. The certificate table of a ~130 KB signed PE sits past the
default `response-body-limit` (100 KiB) and `response-body-minimal-inspect-size`
(40 KiB), so the file must be reassembled from offset 0 for `cert_*` to match.

The test raises `stream.reassembly.depth`, `response-body-limit`, and
`response-body-minimal-inspect-size` and verifies `cert_thumbprint` matches;
the header-based `signature` flag matches regardless. The `input.pcap` is a
frozen fixture built with the `pe-keyword-validation` bundle generators.
