# AF_PACKET IPS with two bonded networks

Ports `qa/live/netns/afp-ips-netns-bond-bridge2.sh` into the live test
framework. One workers-mode Suricata process forwards two independent inline
networks over balance-rr bonds at MTU 9000. HTTP must pass on both networks,
while fragmented and ordinary ICMP echo requests must be dropped before they
reach either server.
