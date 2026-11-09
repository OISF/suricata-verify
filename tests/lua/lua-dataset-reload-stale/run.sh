#!/bin/sh
set -u

SURI="${SRCDIR}/src/suricata"
OUT="${OUTPUT_DIR}"
FIFO="${OUT}/dns.fifo"

rm -rf "$OUT"
mkdir -p "$OUT"
mkfifo "$FIFO"

python3 "${TEST_DIR}/feed.py" "$FIFO" "${OUT}/ready" "${OUT}/go" > "${OUT}/feed.log" 2>&1 &
FEED=$!

"$SURI" -c "${TEST_DIR}/suricata.yaml" -r "$FIFO" -l "$OUT" \
    --set default-rule-path="${TEST_DIR}" > "${OUT}/stdout" 2> "${OUT}/stderr" &
PID=$!

# batch 1: the output script resolves and caches the Dataset handle
for i in $(seq 1 200); do [ -f "${OUT}/ready" ] && break; sleep 0.05; done
sleep 1

# reload the rules: the static set is freed by DatasetPostReloadCleanup()
kill -USR2 $PID
for i in $(seq 1 200); do grep -q "rule reload complete" "${OUT}/stdout" && break; sleep 0.05; done

# batch 2: the cached handle now dangles
touch "${OUT}/go"

wait $FEED
wait $PID
exit $?
