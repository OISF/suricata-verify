#!/bin/bash
#
# This test runs Suricata as background process listening on the lo
# interface with a BPF filter that makes it unlikely that we'll be
# capturing anything. Rule loading is disabled, too.
set -u

export PYTHONPATH=${SRCDIR}/python:${PYTHONPATH:-}

POLL=0.1
TIMEOUT=10
SURICATASC=${SRCDIR}/python/bin/suricatasc
BPF_FILTER='src host 8.8.8.8 and dst host 100.64.0.1'
UNIX_COMMAND_FILENAME=${OUTPUT_DIR}/suricata.sock

function run_suricatasc {
    python3 "${SURICATASC}" -c "$@" "${UNIX_COMMAND_FILENAME}"
}

if ! run_suricatasc version -h > /dev/null; then
    echo "suricatasc not functional" >&2
    exit 1
fi

timeout -k 1 $TIMEOUT "${SRCDIR}/src/suricata" -v \
    -c "${SRCDIR}/suricata.yaml" \
    -l "${OUTPUT_DIR}" \
    --pcap=lo \
    --runmode=workers \
    --set capture.disable-offloading=false \
    --set capture.checksum-validation=none \
    --set pcap.1.threads=2 \
    --set flow.managers=3 \
    --set flow.recyclers=5 \
    --set stats.interval=1 \
    --set rule-files.0=/dev/null \
    --set unix-command.filename="${UNIX_COMMAND_FILENAME}" \
    "${BPF_FILTER}" &

SURICATA_PID=$!

# Cleanup
trap '{ echo trap; kill ${SURICATA_PID} ; exit 1; }' SIGINT SIGTERM ERR

# suricatasc exits with 1 until stats are synchronized
while ! run_suricatasc dump-counters; do
    sleep $POLL
done

run_suricatasc dump-counters > "${OUTPUT_DIR}/dump-counters.json"

run_suricatasc shutdown

trap '' SIGINT SIGTERM ERR

wait $SURICATA_PID
