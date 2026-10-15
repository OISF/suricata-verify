# HTTP bomb cap skips the next gzip body and drops the flow

The control connection sends two brotli bodies that each decompress past 1 MiB
with a ratio above 2048, then a gzip body whose plaintext starts with
`E2EGZIPMARKER`, then an uncompressed `GET /c/after-plain`. `file_data` matches
the marker and `/c/after-plain` is still an HTTP transaction.

The attack connection sends three of the same brotli bodies, then the same
gzip body, then `GET /a/after-plain`. The third bomb reaches
`COMPRESSION_BOMB_LIMIT_REACHED`. The gzip plaintext does not match
`file_data`. `/a/after-plain` produces no HTTP event. That is the same failure
twice. The compressed body never enters detection, and the application layer
is removed for the rest of the flow.

`input.pcap` is produced by `writepcap.py` (Python standard library only).
The brotli body is the 38-byte encoding of 1056768 zero bytes with a 256 KiB
window. A single gzip body cannot reach the default ratio of 2048, so it does
not advance the bomb counter. The test expects the current default cap of 3
and leaves decompression enabled.

https://redmine.openinfosecfoundation.org/issues/9200
