# Test

Check that Suricata behaves as expected with stream.midstream=true and no
midstream-policy set, in IPS mode.

# Behavior

With midstream true, we expect to see alerts and ``http`` events logged, as the
portion of the flow available will be inspected and no exception policy for
midstream will be applied.

# Pcap

Pcap is the result of a curl to www.testmyids.com
