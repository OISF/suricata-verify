# Test

Check and showcase alert verdicts when there are ``alert``, ``pass`` and
``drop`` rules.

# Behavior

It's expected that Suricata will log out alerts for rules 1 and 3. Rule 2 would
match if the flow weren't already 'passed' when it's triggered and also based on
action order, and rule 4 isn't logged out with packet 4 as it's a 'pass' alert.

Moreover, when the http transaction is finished, with packet 6 (pcap_cnt: 6),
we should see an alert for rule 1, as it has a higher priority so is queue as an
alert first, but still see the 'pass' verdict for same packet - which also leads
to no alerts or drops for rule 2, that should trigger for packet 6.

# Pcap

Pcap comes from the test detect-app-layer-protocol-02 and is the result of a
curl to www.testmyids.com.

