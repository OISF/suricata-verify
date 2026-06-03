# DNS forward compression pointer

Test that DNS names using a forward compression pointer are accepted and
logged.

The pcap comes from Redmine #8584. The first DNS request contains two A queries
for `codemonkey.net`; the first QNAME is a compression pointer to the second
query name, which appears later in the DNS message.
