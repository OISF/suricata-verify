# Description

Test verifies the behavior when direction of TCP flow is changed by the probing parser.
Probing parser may change the direction of flow processing packet that contains payload.
This payload must be added to the proper direction stream.

# PCAP

pcap file contains 2 http transactions. The request is missing for the first one.
The second transaction is fully complete. So eve.json must contain one and only anomaly event.
