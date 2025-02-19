# Test Description

Test to investigate that Suricata is properly inspecting and alerting on DNS
transactions, without missing any, in IPS mode.

The difference in this case should only be the pcap_cnt for the events.

## PCAP

dns-tcp-multi.pcap, crafted for this test, shared in the Redmine ticket.

The capture shows three request-response DNS transactions:
Query 1: suricata.io
Query 2: oisf.net
Query 3: suricata.org

We match those against a single rule with `dns.queries.rrname` and inspecting
content `suricata`, so the expectation is to have 4 alerts.

## Related issues

https://redmine.openinfosecfoundation.org/issues/7018
https://redmine.openinfosecfoundation.org/issues/7004
