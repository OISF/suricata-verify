# Description

Test QUIC SNI inspection when a UDP five-tuple is reused for a new QUIC
connection. The first ClientHello contains SNI `Google.com` but does not
progress to a client Handshake packet. A second connection on the same
five-tuple contains SNI `www.dongbeirain.fun`, progresses to the Handshake
stage, and exchanges application data.

Suricata should inspect the second Client Initial, create a QUIC transaction
for its SNI, and trigger the matching rule. Before the fix, Suricata stops
client-direction Initial inspection after the first ClientHello and therefore
misses the second SNI and alert.

# Ticket

https://redmine.openinfosecfoundation.org/issues/8776

# Pull request

https://github.com/OISF/suricata/pull/15979

# PCAP

The PCAP was captured in a controlled environment using a custom Android QUIC
client and a privately operated QUIC server.
