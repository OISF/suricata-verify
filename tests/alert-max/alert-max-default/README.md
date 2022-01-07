Tests that no alert is generated if a packet has more alerts associated
with it that the value for PACKET_ALERT_MAX.
 
Also test that Suricata will fall back to default value if an invalid value
(zero, in the test) is passed in the configuration file.

Therefore, the 16th alert will not be appended to the Packet queue.
