# ruletype-firewall-563-http2-trailer-hook-no-match

HTTP/2 trailer state under firewall: a rule hooked at the trailer state with a buffer that completes at that state, and content that cannot match: the rule is evaluated and fails, so the policy decides.

The pcap is the gRPC shaped stream from `tests/http2-trailer`, whose trailer
block is the only thing that reaches `http2:stream:request_trailers`. The other
stream states fall to the `accept:hook` protocol default policy in
`suricata.yaml`, so the trailer state is the only one a rule is hooked at.

The stream is not blocked and not accepted either: `accept:hook` takes no flow
action, so the flow ends with no action recorded. Compare
`ruletype-firewall-559-http2-trailer-default-policy`, where the state has no
rule at all, and `ruletype-firewall-564-http2-trailer-hook-lte-form`, where a
rule hooked up to this state does match and accepts the flow.
