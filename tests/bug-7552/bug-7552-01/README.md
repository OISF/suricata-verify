# Description

Created when a bug was found - Transaction gets cleaned by
AppLayerParserTransactionsCleanup before detection is run in the to_client
direction when stream.midstream=true and first packet is to client direction.

https://redmine.openinfosecfoundation.org/issues/7552

# PCAP

PCAP created by selecting packets from ../http-gap-simple/input.pcap