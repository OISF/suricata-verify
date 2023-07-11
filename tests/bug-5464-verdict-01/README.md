# Test

Check and showcase alert verdicts when there are ``reject``, ``pass`` and
``drop`` rules.

# Behavior

We expect to see ``drop`` and ``alert`` events with info about the ``reject``
that will happen due to rule 2 for pcap_cnt 1 this is due to ``drop`` and ``reject``
rules being triggered. For the other packets, we should see drops due to the
flow being dropped as a result of rule 1.

# Pcap

Pcap comes from the test detect-app-layer-protocol-02 and is the result of a
curl to www.testmyids.com.
