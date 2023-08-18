# Test

Check that the midstream exception policy is properly applied in case Suricata
has stream midstream pick-up sessions enabled. In this test the exception policy
for midstream sessions is set to ``bypass``. This test is for IDS mode.

# Behavior

We expect Suri to error out without starting as ``bypass`` isn't a valid
exception policy value when midstream picku-up sessions are enabled.

# Pcap

Pcap comes from the test ``alert-testmyids-midstream5`` and is the result of a
curl to www.testmyids.com.
