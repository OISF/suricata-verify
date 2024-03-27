# Test Description
This test demonstrates that fast_pattern along with base64_data
should fail with Suricata instead of silently passing through even
if it is followed by several valid base64_data buffers.

## PCAP
None

## Related issues
https://redmine.openinfosecfoundation.org/issues/5220
