# Test Description

Tests the `payload-only-classtypes` feature which allows filtering payload extraction in EVE alerts based on the rule's classtype.

The test uses three rules:
1. Rule with classtype `extract-me` (in the filter list) - payload SHOULD be extracted
2. Rule with classtype `dont-extract-me` (not in the filter list) - payload should NOT be extracted
3. Rule without any classtype - payload should NOT be extracted (when filtering is enabled)

## PCAP

HTTP traffic with JPG file requests from two different subnets (10.1.1.x and 10.1.2.x) to trigger different rules.

## Related issues

Feature: Add `payload-only-classtypes` filtering to suricata.yaml to filter payload dump by classtype.

https://github.com/OISF/suricata/pull/14680