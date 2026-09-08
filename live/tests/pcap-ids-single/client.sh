#!/bin/bash
set -euo pipefail

socket="${OUTDIR}/suricata.socket"
eve="${OUTDIR}/eve.json"
target=10.200.0.1

sc() {
    "${SURICATASC}" -c "$1" "${socket}"
}

expect_return() {
    local command="$1"
    local expected="${2:-OK}"
    local json
    json=$(sc "${command}")
    echo "${json}"
    test "$(jq -r '.return' <<<"${json}")" = "${expected}"
}

wait_for_ok() {
    local command="$1"
    local json
    for _ in $(seq 1 40); do
        json=$(sc "${command}")
        if [ "$(jq -r '.return' <<<"${json}")" = OK ]; then
            echo "${json}"
            return 0
        fi
        sleep 0.25
    done
    echo "${json}"
    echo "error: command did not return OK: ${command}"
    return 1
}

wait_for_alerts() {
    local sid="$1"
    local expected="$2"
    local count=0
    for _ in $(seq 1 40); do
        count=$(jq -c "select(.event_type == \"alert\" and .alert.signature_id == ${sid})" \
            "${eve}" 2>/dev/null | wc -l)
        if [ "${count}" -ge "${expected}" ]; then
            return 0
        fi
        sleep 0.25
    done
    echo "error: expected at least ${expected} alerts for sid ${sid}, got ${count}"
    return 1
}

ping_once() {
    ip netns exec client0 ping -c 1 -W 1 "${target}"
}

ping_once
wait_for_alerts 222 1
expect_return "dataset-clear ipv4-list ipv4"
ping_once
wait_for_alerts 222 2

json=$(sc "dataset-add ipv6-list ip 192.168.1.1")
echo "${json}"
test "$(jq -r '.message' <<<"${json}")" = "data added"
json=$(sc "dataset-lookup ipv6-list ip ::ffff:c0a8:0101")
echo "${json}"
test "$(jq -r '.message' <<<"${json}")" = "item found in set"
json=$(sc "dataset-add ipv6-list ip ::ffff:c0a8:0z0z")
echo "${json}"
test "$(jq -r '.message' <<<"${json}")" = "failed to add data"

json=$(sc "iface-list")
echo "${json}"
iface=$(jq -r '.message.ifaces[0]' <<<"${json}")
sleep 1
json=$(sc "iface-stat ${iface}")
echo "${json}"
test "$(jq -r '.message.pkts > 0' <<<"${json}")" = true

cp "${TESTDIR}/icmp2.rules" "${OUTDIR}/suricata.rules"
expect_return "reload-rules"

sc "iface-bypassed-stat"
json=$(sc "capture-mode")
echo "${json}"
test "$(jq -r '.message' <<<"${json}")" = PCAP_DEV
json=$(wait_for_ok "dump-counters")
test "$(jq -r '.message.uptime >= 0' <<<"${json}")" = true
sc "memcap-list"
json=$(sc "running-mode")
echo "${json}"
test "$(jq -r '.message' <<<"${json}")" = "${EXPECTED_RUNMODE}"
sc "version"
json=$(sc "uptime")
echo "${json}"
test "$(jq -r '.message >= 0' <<<"${json}")" = true

expect_return "add-hostbit ${target} test 60"
ping_once
wait_for_alerts 2 1
json=$(sc "list-hostbit ${target}")
echo "${json}"
test "$(jq -r '.message.hostbits[0].name' <<<"${json}")" = test
expect_return "remove-hostbit ${target} test"
