# Test Description

Test earlier alert matches after trigger raw stream reassembly when there's a
completed DNS TCP transaction.

## PCAP

dns-tcp-multi.pcap, crafted for this test, shared in the Redmine ticket.

The capture shows three request-response DNS transactions:
Query 1: suricata.io
Query 2: oisf.net
Query 3: suricata.org

## Behavior

We match those against a single payload rule without any DNS keywords,
and inspecting content `suricata|02|`. Ideally, the expectation is to have 2 alerts,
for the portion of the stream associated with Query 1 - that's because on the
wire we observe that for Query three the content is `suricata|03|`.

For IPS mode, as a larger portion of the stream buffer is kept available, and as
it still contains the matching bytes, we'll see more alerts triggered.

## Related issues

https://redmine.openinfosecfoundation.org/issues/7018
https://redmine.openinfosecfoundation.org/issues/7004
