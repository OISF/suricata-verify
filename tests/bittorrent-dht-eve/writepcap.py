#!/usr/bin/env python
from scapy.all import *

pkts = []

# ping and response
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.2")/ \
    UDP(sport=40000, dport=50000)/ \
    "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.2", dst="190.0.0.1")/ \
    UDP(sport=50000, dport=40000)/ \
    "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"

# ping and error response
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.3")/ \
    UDP(sport=20000, dport=30000)/ \
    "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.3", dst="190.0.0.1")/ \
    UDP(sport=30000, dport=20000)/ \
    "d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"

# find_node and response
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.3")/ \
    UDP(sport=20000, dport=30000)/ \
    "d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:v4:UT011:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.3", dst="190.0.0.1")/ \
    UDP(sport=30000, dport=20000)/ \
    "d1:rd2:id20:0123456789abcdefghij5:nodes9:def456...e1:t2:aa1:v4:UT011:y1:re"

# get_peers and response with values param
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.3")/ \
    UDP(sport=20000, dport=30000)/ \
    "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:v4:UT021:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.3", dst="190.0.0.1")/ \
    UDP(sport=30000, dport=20000)/ \
    "d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:v4:UT121:y1:re"

# get_peers and response with nodes param
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.3")/ \
    UDP(sport=20000, dport=30000)/ \
    "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.3", dst="190.0.0.1")/ \
    UDP(sport=30000, dport=20000)/ \
    "d1:rd2:id20:abcdefghij01234567895:nodes9:def456...5:token8:aoeusnthe1:t2:aa1:y1:re"

# announce_peer and response
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.3")/ \
    UDP(sport=20000, dport=30000)/ \
    "d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.3", dst="190.0.0.1")/ \
    UDP(sport=30000, dport=20000)/ \
    "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"

# announce_peer with implied_port param and response
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.3")/ \
    UDP(sport=20000, dport=30000)/ \
    "d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.3", dst="190.0.0.1")/ \
    UDP(sport=30000, dport=20000)/ \
    "d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"

# malformed packet
pkts += Ether()/ \
    IP(src="190.0.0.1", dst="190.0.0.3")/ \
    UDP(sport=20000, dport=30000)/ \
    "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:y1:qe"

pkts += Ether()/ \
    IP(src="190.0.0.3", dst="190.0.0.1")/ \
    UDP(sport=30000, dport=20000)/ \
    "d1:eli203e16:Malformed Packete1:t2:aa1:y1:ee"

wrpcap("input.pcap", pkts)
