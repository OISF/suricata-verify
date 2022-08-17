# Test

Check that Suricata behaves as expected with no midstream-policy set (that is,
with default behavior), in IPS mode, in a stream first seen by Suricata in
SYNACK stage.

# Behavior

With midstream true but no exception policy for midstream set we expect to see
alerts and ``http`` events logged, as the portion of the flow available will be
inspected and no exception policy for midstream will be applied.

# Pcap

Pcap is the result of a curl to www.testmyids.com
