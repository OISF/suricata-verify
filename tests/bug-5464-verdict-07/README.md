# Test

Showcase and test verdict output with reject for UDP protocol.

# Behavior

We expect to see 2 alerts with the verdict field, informing
`verdict.reject: [icmp-prohib]`.

# PCAP

Reused pcap from test bug-5633-gre-01.
