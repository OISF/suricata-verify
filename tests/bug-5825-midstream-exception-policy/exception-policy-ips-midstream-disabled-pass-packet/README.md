# Test

Check that the midstream exception policy is properly applied in case Suricata
has stream midstream pick-up sessions disabled. In this test the exception policy
for midstream sessions is set to ``pass-packet``. This test is for IPS mode.

# Behavior

We expect Suri to error out without starting as ``pass-packet`` isn't a valid
exception policy value.


# Pcap

Pcap comes from the test ``exception-policy-midstream-03`` and is the result of a
curl to www.testmyids.com.
