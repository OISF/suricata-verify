---
tags:
- http
---

# AF_PACKET IPS with overlapping alert and drop rules over HTTP

Suricata runs inline in AF_PACKET copy-mode IPS with two copies of the
classic testmyids.org "GPL ATTACK_RESPONSE id check returned root"
rule with identical match conditions: sid 1 is a generic alert rule
matching any source and destination, while sid 2 is a drop rule
limited to traffic to the client (10.200.0.2), such as the server
responses.

The client fetches a benign page which must succeed, then the
testmyids page whose response contains
`uid=0(root) gid=0(root) groups=0(root)`. That response matches both
rules and is dropped, so the fetch must fail.

The checks verify that both rules alerted with their expected actions
("allowed" for sid 1, "blocked" for sid 2, on the same dropped
response), that the benign transaction completed normally, and that
the IPS blocked packets.
