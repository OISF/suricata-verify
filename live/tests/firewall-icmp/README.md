---
tags:
- firewall
- icmp
---

A simple ICMP firewall test.

- We first start with an empty firewall ruleset and attempt a ping
  which we accept to fail.
- Then we update the firewall rules with a rule to allow ICMP and
  trigger a reload.
- Then test that a ping is allowed.
