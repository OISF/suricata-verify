# Description

SIP over UDP with midstream enabled. Once the flow is detected from the
client's request, a request sent by the server, NOTIFY detected with the
probing parser or MESSAGE detected with a plain pattern, matches the request
patterns through the other direction: the flow must not be reversed, so that
the server's response and the client's next request are still parsed in the
right direction. A flow whose first packet is a response must still be
reversed.

The requests sent by the server are not checked: parsing them depends on the
support of requests in both directions.

# PCAP

Created with `create_pcap.py`.
