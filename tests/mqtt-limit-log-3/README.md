# Test

Test if, for MQTT subscribe messages with multiple topics, the truncation
via the `mqtt.string-log-limit` option works as intended when the concatenation
of the topic names exceeds the limit while each individual topic name is within
the limit. This was an additional requirement to address circumventing the limit
to cause excessive logging by simply creating more topics instead of crafting
longer topic names.

For example, for the topics:

 * `topicX`
 * `topicY`
 * `topicZ`

 and a max length of 10, we will get the following result:

 * `topicX`
 * `topi[truncated 2 additional bytes]`

## PCAP

Using the one from the `mqtt5-sub-userpass` test.

## Ticket

https://redmine.openinfosecfoundation.org/issues/6984
