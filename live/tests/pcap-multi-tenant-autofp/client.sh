#!/bin/bash
set -euo pipefail

socket="${OUTDIR}/suricata.socket"
tenant="${OUTDIR}/tenant-1.yaml"

expect_return() {
    local command="$1"
    local expected="${2:-OK}"
    local json
    json=$(timeout --kill-after=60 30 "${SURICATASC}" -c "${command}" "${socket}")
    echo "${json}"
    test "$(jq -r '.return' <<<"${json}")" = "${expected}"
}

ip netns exec client0 ping -c 1 -W 1 10.200.0.1

# Match the legacy test's startup delay. The engine-ready message can precede
# multi-tenant management becoming reliable under load.
sleep 15

expect_return "register-tenant 2 ${tenant}"
expect_return "reload-tenants"
expect_return "register-tenant 3 ${tenant}"
expect_return "reload-tenants"
expect_return "unregister-tenant 2"
expect_return "unregister-tenant 3"
expect_return "unregister-tenant 5" NOK
expect_return "reload-tenants"
