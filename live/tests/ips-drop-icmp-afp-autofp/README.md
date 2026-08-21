A copy of the `ips-drop-icmp` AF_PACKET IPS test that runs Suricata with
`--runmode autofp`.

Suricata runs inline with AF_PACKET copy-mode IPS and a single rule that drops
ICMP echo requests. HTTP traffic must still pass, ICMP must be dropped, and no
echo requests should reach the server.
