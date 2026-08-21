A port of "nfq-fw-netns-route" from the Suricata repo to this testing
harness.

Suricata runs as a NFQUEUE router enforcing firewall rules. The default
policy is drop; accept rules allow HTTP. The curl request triggers the
request_line alert but is dropped (its user-agent is not accepted), while
the wget request is accepted. A rule reload then swaps in a second rule
set. Uses the L3 rule variants since NFQUEUE operates at layer 3.
