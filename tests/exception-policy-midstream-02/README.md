# Test

Check that the midstream-policy is properly set to fail closed when
stream.midstream-policy=drop-flow in IPS mode in a stream first seen by Suricata
in SYNACK stage.

# Behavior

Neither the alert or anomaly events that would be logged with default behavior
will show, as the flow is being dropped.

# Traffic Description

TCP async traffic with only the server to client side of a IMAP session

# Pcap

Pcap from https://github.com/mtimebombm/suricata/blob/master/imap-server.pcap
