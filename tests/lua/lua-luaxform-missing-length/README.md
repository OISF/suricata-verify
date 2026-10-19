# lua-luaxform-missing-length

A transform script that returns only the buffer (no length) leaves the
second result nil. The nil must be rejected, not read as a zero length:
reading it as zero would zero the inspection buffer after the
allocating `to_lowercase` transform ran, suppressing the content match
with no error. The rejected call keeps the (lowercased) buffer and
counts in `transform.lua.errors`.

input.pcap: one HTTP/1.1 GET and a 200 response with a small body
(`python3 mkpcap.py input.pcap <b64 body>`).
