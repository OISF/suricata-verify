# Description

Test proper de-init of capture-bypassed flows.
Workers should not time-out and remove capture-byppased flows, they should leave it to FlowManager.

# Ticket

https://redmine.openinfosecfoundation.org/issues/8442

# PCAP

PCAP contains 100 TCP packets with port 443 followed by 100 TCP packets with port 400