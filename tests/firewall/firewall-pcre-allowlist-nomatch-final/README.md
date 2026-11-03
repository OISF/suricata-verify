# The deferral is bounded: the miss becomes final when the state completes

Same split-header request and scaffolding as `firewall-pcre-allowlist-split-headers`, with the
allow-list rule's pattern absent from the traffic.

While the header block is incomplete the rule's miss is not final (`-2`, revisited), so no
default is applied. On the packet that completes the block the engine sits below the
transaction's progress, the miss is final, and `request_headers`'s default policy decides: the
`2201001` alert at that packet and a dropped flow.

This is the half the other fixture cannot see: with the deferral made unconditional, every check
in `firewall-pcre-allowlist-split-headers` stays green while the hook's default stops firing.
