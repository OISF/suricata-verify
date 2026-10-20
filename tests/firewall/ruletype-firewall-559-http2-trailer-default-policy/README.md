# ruletype-firewall-559-http2-trailer-default-policy

HTTP/2 trailer state under firewall: no rule and no per state policy override, under an accept:hook protocol default policy: a stream that only reaches a trailer block must not be blocked.

The pcap is the gRPC shaped stream from `tests/http2-trailer`, whose trailer
block is the only thing that reaches `http2:stream:request_trailers`. The other
stream states fall to the `accept:hook` protocol default policy in
`suricata.yaml`, so the trailer state's own policy decides. That the state's built in default is the
same `accept:hook` is pinned by `engine-analysis-state-tables`.
