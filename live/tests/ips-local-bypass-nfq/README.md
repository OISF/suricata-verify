---
tags:
- bypass
- local
---

# IPS with local bypass test

Test Suricata's own local bypass in NFQ IPS mode.
The test checks that a flow matched by a `bypass` rule is bypassed by Suricata,
while a client and server verify that traffic still flows end to end.
