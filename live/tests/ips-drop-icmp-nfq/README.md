A port of "afp-ips-netns-bridge" (inline environment) and "nfq-ips-netns-route"
(nfq environment) from the Suricata repo to this testing harness.

Suricata runs inline (AF_PACKET copy-mode IPS or NFQUEUE) with a single
rule that drops ICMP echo requests. HTTP traffic must still pass, ICMP
must be dropped, and no echo requests should reach the server.
