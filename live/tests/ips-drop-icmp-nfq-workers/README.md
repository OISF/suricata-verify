A copy of the `ips-drop-icmp` NFQ IPS test that runs Suricata with
`--runmode workers`.

Suricata runs inline with NFQUEUE and a single rule that drops ICMP echo
requests. HTTP traffic must still pass, ICMP must be dropped, and no echo
requests should reach the server.
