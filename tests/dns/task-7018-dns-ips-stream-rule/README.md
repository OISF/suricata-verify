# Test Description

Test for alert matches after triggering raw stream reassembly when there's a
completed DNS TCP transaction.

## PCAP

dns-tcp-multi.pcap, crafted for this test, shared in the Redmine ticket (#7004).

The capture shows three request-response DNS transactions:
Query 1: suricata.io
Query 2: oisf.net
Query 3: suricata.org

## Behavior

We match those against a single payload rule without any DNS keywords,
and inspecting for content `suricata|02|`. The expectation is to have 2 alerts
for the portion of the stream associated with Query 1 - that's because on the
wire we observe that for Query 3 the content is `suricata|03|`.

### Observed [undesired] behavior

While Suricata is matching on the correct traffic, for IPS mode, as a larger
portion of the stream buffer is kept available, and as it still contains the
matching bytes, more alerts are triggered, and will actually log the transaction
for Query 3 (`oisf.net`).

## Related issues

https://redmine.openinfosecfoundation.org/issues/7018
https://redmine.openinfosecfoundation.org/issues/7004
