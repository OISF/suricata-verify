# Description

SIP sessions over TCP picked up midstream, where the first data seen is a
request sent by the client while the flow was created in the opposite
direction. The flow must be reversed and the request parsed as a request,
both for INVITE, detected with a plain pattern, and for NOTIFY and OPTIONS,
detected with a pattern confirmed by the probing parser. OPTIONS also matches
the HTTP/1 pattern, which the SIP probing parser takes precedence over.

# PCAP

Created with `create_pcap.py`.
