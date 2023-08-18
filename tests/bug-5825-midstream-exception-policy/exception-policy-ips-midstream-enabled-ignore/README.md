# Test

Check that the midstream exception policy is properly applied in case Suricata
has stream midstream pick-up sessions enabled. In this test the exception policy
for midstream sessions is set to ``ignore``. This test is for IPS mode.

# Behavior

We expect to see alerts and ``http`` events logged, as the flow will
be inspected.

# Pcap

Pcap comes from the test ``alert-testmyids-midstream5`` and is the result of a
curl to www.testmyids.com.
