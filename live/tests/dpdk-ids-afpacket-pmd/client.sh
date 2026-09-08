#!/bin/bash
set -euo pipefail

socket="${OUTDIR}/suricata.socket"
eve="${OUTDIR}/eve.json"
target=10.200.0.1

# Drive traffic through the IDS bridge while exercising Suricata's Unix socket
# API. Alerts are asynchronous, so helpers below poll instead of relying on
# fixed sleeps.

# Run one command through suricatasc and return its JSON response.
sc() {
    "${SURICATASC}" -c "$1" "${socket}"
}

# Require a socket command to return the expected status (OK by default).
expect_return() {
    local command="$1"
    local expected="${2:-OK}"
    local json
    json=$(sc "${command}")
    echo "${json}"
    test "$(jq -r '.return' <<<"${json}")" = "${expected}"
}

# Some socket commands can briefly return NOK while a reload is completing.
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

# Wait until eve.json contains at least the requested number of alerts for SID.
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

# The initial rules alert on ICMP and add its destination to ipv4-list. Clear
# the dataset between pings to verify both packet inspection and dataset API
# handling; the final checks expect two alerts from each initial rule.
ping_once
wait_for_alerts 222 1
expect_return "dataset-clear ipv4-list ipv4"
ping_once
wait_for_alerts 222 2

# Discover the DPDK virtual interface and confirm it has captured traffic.
json=$(sc "iface-list")
echo "${json}"
iface=$(jq -r '.message.ifaces[0]' <<<"${json}")
sleep 1 # Allow the interface counters to be published.
json=$(sc "iface-stat ${iface}")
echo "${json}"
test "$(jq -r '.message.pkts > 0' <<<"${json}")" = true

# Replace the ruleset with a hostbit-dependent rule and reload it live.
cp "${TESTDIR}/icmp2.rules" "${OUTDIR}/suricata.rules"
expect_return "reload-rules"

# Smoke-test the remaining management commands and verify DPDK/workers are the
# active capture and running modes. Commands without assertions still fail the
# script if suricatasc itself cannot execute them.
sc "iface-bypassed-stat"
json=$(sc "capture-mode")
echo "${json}"
test "$(jq -r '.message' <<<"${json}")" = "${EXPECTED_CAPTURE_MODE}"
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

# Set the hostbit required by the reloaded rule, then prove that another ICMP
# packet alerts before removing the hostbit again.
expect_return "add-hostbit ${target} test 60"
ping_once
wait_for_alerts 2 1
json=$(sc "list-hostbit ${target}")
echo "${json}"
test "$(jq -r '.message.hostbits[0].name' <<<"${json}")" = test
expect_return "remove-hostbit ${target} test"
