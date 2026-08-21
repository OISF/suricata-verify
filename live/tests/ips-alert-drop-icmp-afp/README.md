# AF_PACKET IPS with overlapping alert and drop rules

Suricata runs inline in AF_PACKET copy-mode IPS with two rules that
have identical match conditions (ICMP echo request), but different
actions and rule headers:

- sid 1: a generic alert rule matching any source and destination
- sid 2: a drop rule limited to echo requests from the client
  (10.200.0.2) to the server (10.200.0.1)

Pings from the client to the server must fail as they are dropped by
sid 2, while pings from the server to the client only match the alert
rule and must succeed.

The checks verify that both rules alerted with their expected actions
("allowed" for sid 1, "blocked" for sid 2, including on the same
dropped packets), and that the IPS blocked the dropped pings.
