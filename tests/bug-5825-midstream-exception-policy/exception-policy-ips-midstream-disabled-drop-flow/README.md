# Test

Check that the midstream exception policy is properly applied in case Suricata
has stream midstream pick-up sessions disabled. In this test the exception policy
for midstream sessions is set to ``drop-flow``. This test is for IPS mode.

# Behavior

We expect to see no alerts nor ``http`` events logged, as the session won't be
tracked. The flow should be dropped.

# Pcap

Pcap comes from the test ``alert-testmyids-midstream5`` and is the result of a
curl to www.testmyids.com.
