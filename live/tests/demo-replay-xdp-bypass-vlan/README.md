---
tags:
- bypass
- replay
- xdp
---

Demo live IDS replay test based on the test in
https://github.com/OISF/suricata-verify/pull/3204.

The pcap contains one VLAN-tagged TCP flow with 100 packets. The client script
replays it from the client namespace onto the IDS bridge path with `tcpreplay`.

Ticket: https://redmine.openinfosecfoundation.org/issues/8699
