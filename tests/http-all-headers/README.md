# HTTP dump headers

This test verifies that the flag outputs.eve-log.types.http.dump-all-headers set
to "both" will make suricata dump all headers per HTTP transaction, for both
requests and response.

To simplify the test, the check will verify the length of the headers in the json
object and the header name and value of one request header and one response
header.

The pcap file is downloaded from

```
https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap
```
