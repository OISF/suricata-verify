# Redmine issue 8961 IKE handler result

The pcap contains three malformed IKEv1 UDP datagrams:

- valid generic payload framing, but an empty Security Association body;
- a header length one byte larger than the datagram;
- a header length one byte smaller than the datagram.

The top-level IKE parser must propagate the version-specific parser result and
reject ISAKMP header lengths that do not match the complete UDP payload. The
three datagrams must produce three IKE app-layer parser errors.

Regenerate `input.pcap` with:

```sh
./writepcap.py
```
