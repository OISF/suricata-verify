Test for checking the working of icmp_id keyword by creating 1 rule and matching a crafted packet against them. The packet is an ICMP packet with no "id" field, therefore the rule should not trigger.

PCAP created with scapy.
