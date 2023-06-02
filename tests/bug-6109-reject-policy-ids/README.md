# Test

Check that the midstream exception policy is properly applied in case Suricata
has stream midstream pick-up sessions disabled. In this test the exception policy
for midstream sessions is set to ``reject``. This test is for IDS mode.

# Behavior

We expect to see no alerts nor ``http`` events logged, as the session won't be
tracked. The flow should be rejected, but not dropped, as in IDS mode there's no
drop.

# Pcap

Pcap comes from the test ``exception-policy-midstream-03`` and is the result of a
curl to www.testmyids.com.

# Note

This test triggers Bug 6109 - exception/policy: reject changes flow action in IDS mode
