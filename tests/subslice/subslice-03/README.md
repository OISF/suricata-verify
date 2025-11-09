# Description

Test the subslice transform with negative offset exceeding buffer length.
When truncate is specified, excessive negative offsets should be clamped to the buffer length.

For example, with buffer "curl/7.64.1" (11 characters):
- subslice: -20, truncate should be treated as -11 (start at position 0)
- subslice: -20, 5, truncate should start at 0 and take 5 bytes

https://redmine.openinfosecfoundation.org/issues/7672

Issue: 7672

# PCAP

The pcap comes from test http2-range.
This pcap has both HTTP1 and HTTP2.
