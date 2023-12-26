Test the `dns.rcode` header value.

The PCAP here used the pcap from test dns-eve-v2-udp-nxdomain-soa with
hex editing header flags to have the DNS query have something in the `rcode`
section.

Redmine ticket: https://redmine.openinfosecfoundation.org/issues/6621
