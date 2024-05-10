# Test

Test if, for MQTT publish/subscribe messages with long content, the truncation
via the `mqtt.msg-log-limit` option works as intended for a maximum length
longer than the actual length of the message payload. This is done by
checking if log entries in the EVE-JSON are unrestricted in length.

## PCAP

Using the one from the `mqtt-limit-2` test.

## Ticket

https://redmine.openinfosecfoundation.org/issues/6984
