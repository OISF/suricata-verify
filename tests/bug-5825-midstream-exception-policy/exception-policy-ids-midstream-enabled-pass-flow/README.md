# Test

Check that the midstream exception policy is properly applied in case Suricata
has stream midstream pick-up sessions enabled. In this test the exception policy
for midstream sessions is set to ``pass-flow``. This test is for IDS mode.

# Behavior

We expect to see no alerts, since detection won't run due to ``pass-flow``, but
to see ``http`` events logged, as the flow will be inspected.

# Pcap

Pcap comes from the test ``alert-testmyids-midstream5`` and is the result of a
curl to www.testmyids.com.
