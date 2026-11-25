Tests the dcerpc.is_fragmented keyword over DCE/RPC-over-UDP (connectionless).

For UDP the keyword treats a transaction whose flags1 has the fragment bit
(0x04, PFCL1_FRAG) set as fragmented. The pcap (see
dcerpc_is_fragmented_udp_scapy.py) has two REQUEST PDUs: the first with
flags1=0x04 (fragmented) and the second with flags1=0x00 (not fragmented). The
rules confirm is_fragmented:true matches the first and is_fragmented:false the
second.
