# Description

Test DNS over UDP with midstream enabled when the first packet comes from the
server and is not recognized as DNS (a truncated response). Detection fails
on that direction, so the following query from the client must still reverse
the flow: the query and its response must be parsed in the right direction.

# PCAP

Created with `create_pcap.py`.
