# Test

Showcase change of behavior from Suricata-7.0.5 to Suricata-7.0.6.
Before, a non-stream rule that matched traffic associated with an app-layer
transaction would result in app-layer metadata being logged with the alert, if
metadata was enabled. Starting with 7.0.6, this will only be achieved if the
rule is an app-layer/stream one.

### Pcap

Packet capture resulting of a curl to suricata.io.

### Ticket

https://redmine.openinfosecfoundation.org/issues/7199
