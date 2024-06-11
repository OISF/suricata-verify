# Test

Test if, for MQTT publish/subscribe messages with long content, the truncation
via the `mqtt.string-log-limit` option works as intended for a maximum length
shorter than the actual length of the message payload. This is done by
checking if the log entries in the EVE-JSON are of the correct length and also
contain the truncation tag.

## PCAP

Using the one from the `mqtt-limit-2` test.

## Ticket

https://redmine.openinfosecfoundation.org/issues/6984
