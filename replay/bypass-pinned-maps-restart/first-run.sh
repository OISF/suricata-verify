#!/bin/bash
# First Suricata run of the test: bypass the flows of the pcap and stop. The
# XDP filter and the pinned maps stay on the test interface for the second
# run, which is the one started by the test runner.
set -e
out=run1

# start without the XDP filter and the pinned maps of an earlier failed test
ip link set dev ${INTERFACE} xdpgeneric off
rm -f /sys/fs/bpf/suricata-${INTERFACE}-*

mkdir $out
${SRCDIR}/src/suricata -c ${TEST_DIR}/suricata.yaml -S ${TEST_DIR}/test.rules \
    -l $out -i ${INTERFACE} --init-errors-fatal \
    --set classification-file=${SRCDIR}/etc/classification.config \
    --set reference-config-file=${SRCDIR}/etc/reference.config \
    --set af-packet.0.xdp-filter-file=${SRCDIR}/ebpf/xdp_filter.bpf \
    > $out/stdout 2> $out/stderr &
pid=$!
# no Suricata is left running if this script fails
trap 'kill -KILL $pid 2>/dev/null || true' EXIT
started=no
for i in $(seq 1 100); do
    if grep -q "Engine started" $out/stdout; then
        started=yes
        break
    fi
    kill -0 $pid 2>/dev/null || break
    sleep 0.1
done
if [ $started = no ]; then
    echo "Suricata did not start" >&2
    exit 1
fi

tcpreplay -i ${REPLAY_INTERFACE} ${TEST_DIR}/../bypass-stats-shutdown/input.pcap > /dev/null
sleep 1
kill -TERM $pid
wait $pid
trap - EXIT
bpftool -j map dump pinned /sys/fs/bpf/suricata-${INTERFACE}-flow_table_v4 > $out/flow_table_v4.json
