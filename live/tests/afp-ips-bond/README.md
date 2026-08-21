# AF_PACKET IPS with one bonded network

Ports `qa/live/netns/afp-ips-netns-bond-bridge.sh` into the live test
framework using the framework's `10.200.0.0/24` address scheme. One
workers-mode Suricata process forwards an inline network over two-member
balance-rr bonds at MTU 9000. HTTP must pass while fragmented ICMP echo
requests must be dropped before they reach the server.
