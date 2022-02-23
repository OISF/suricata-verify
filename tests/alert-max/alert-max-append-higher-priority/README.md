This is a test for corner cases scenarios where we have a low packet_alert_max
configuration, and we try to add a signature with an id which is lower than an
existing queued signature.

The expected behavior is as follows:
- Rules with sid 1, 2, and 4 should not match (there to ensure we have the right
scenario in terms of internal ids and signature ordering)
- 1st rule triggered: sid 4 (internal id 3)
- 2nd rule triggered: sid 6 (internal id 5)
- 3rd rule triggered: sid 8 (internal id 7)
- 4th rule triggered: sid 7 (internal id 6)

In this scenario, packet_alert_max is set to 3, meaning that one of the rules 
should not generate an alert, at the end, due to being discarded from the Packet's
alert queue.

Expected final result:

Alerts for sids 4, 6 and 7. Sid 8 should be discarded, as its higher id implies a 
lower priority rule - discarded. 
