#! /bin/sh

failed=no

# We should get a "SURICATA Applayer Mismatch protocol both
# directions" alert.
n=$(cat eve.json | \
	jq -c 'select(.alert.signature_id == 2260000)' | \
	wc -l | xargs)
if [ "$n" != 1 ]; then
    echo "expected 1 event with SID 2260000"
    failed=yes
fi

# We should have a flow event with app_proto = http and app_proto_tc = ssh.
n=$(cat eve.json | \
	jq -c 'select(.event_type == "flow") | select(.app_proto == "http") | select(.app_proto_tc == "ssh")' | \
	wc -l | xargs)
if [ "$n" != 1 ]; then
    echo "expected 1 event with app_proto http and app_proto_tc ssh"
    failed=yes
fi

if [ "${failed}" = "yes" ]; then
    exit 1
fi

exit 0

