# Transform gunzip UAF regression

This test covers Redmine security ticket #8536:
`detect/transform: use-after-free in decompress transform pipeline`.

The pcap contains a single HTTP request whose URI path starts with
`base64(gzip("A"))`. The rule decodes the URI with `from_base64`, then applies
`gunzip: max-size 8192`. Before the fix, an ASAN-enabled Suricata build reads
from the inspection buffer allocation freed by `SCInspectionBufferCheckAndExpand`
and aborts with a heap-use-after-free.

The pcap and rule are from the ticket reproduction.
