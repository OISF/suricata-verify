# Test Description
This test demonstrates an invalid combination of base64_data with fast_pattern even
in case when there are multiple base64_data in a rule. The rule processing shall
stop the moment the first fast_pattern with base64_data is encountered.

## PCAP
None

## Related issues
https://redmine.openinfosecfoundation.org/issues/5220
