#!/bin/bash
set -euo pipefail

ping_size() {
    ip netns exec client0 ping -c 3 -i 0.2 -W 2 -M do -s "$1" -p deadbeef 10.200.0.1
}

# 1442 byte frames span 2 mbufs, 9014 byte jumbo frames span 8 mbufs.
ping_size 1400
ping_size 8972

# The last frames may still be in flight after ping exits; wait for their
# alerts before shutting down. The checks report any shortfall.
for _ in $(seq 1 40); do
    count=$(jq -c 'select(.event_type == "alert")' "${OUTDIR}/eve.json" 2>/dev/null | wc -l)
    if [ "${count}" -ge 12 ]; then
        exit 0
    fi
    sleep 0.25
done
