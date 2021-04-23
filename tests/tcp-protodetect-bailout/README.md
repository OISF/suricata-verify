# Description

Test absence of impossible case in `TCPProtoDetectCheckBailConditions`

# PCAP

The pcap comes from https://redmine.openinfosecfoundation.org/issues/4171

This pcap was produced with
1. python script from http-connect S-V test
2. Mixed packets order with editcap and mergecap (1-6,10,9,7-8)
3. Manually crafted to increase the TCP option window scale to 7 (128) on both sides
4. Manually crafted to increase the sequence number of now packet 7 (second packet with tcp payload) adding 0x100000 (as much needed to trigger `DEBUG_VALIDATE_BUG_ON(size_ts > 1000000UL);`)
