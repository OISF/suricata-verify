# ruletype-firewall-560-http2-trailer-policy-drop

HTTP/2 trailer state under firewall: firewall policies set drop:flow for the trailer states: the stream must be blocked when it reaches one.

The pcap is the gRPC shaped stream from `tests/http2-trailer`, whose trailer
block is the only thing that reaches `http2:stream:request_trailers`. The other
stream states fall to the `accept:hook` protocol default policy in
`suricata.yaml`, so the trailer state's own policy decides.
