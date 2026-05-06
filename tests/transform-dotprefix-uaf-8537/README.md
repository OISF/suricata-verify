# Transform dotprefix UAF regression

This test covers Redmine security ticket #8537:
`detect/transform: heap-use-after-free in inspection-buffer transform chaining`.

The pcap contains an HTTP request with a 4096-byte Host header. The rule applies
`to_lowercase` and then `dotprefix` to `http.host`. Before the fix, the first
transform makes `buffer->inspect` point into `buffer->buf`; `dotprefix` then
grows the buffer from 4096 to 8192 bytes, and an ASAN-enabled Suricata build
aborts after reading from the freed old allocation.

The pcap and rule are from the ticket reproduction.
