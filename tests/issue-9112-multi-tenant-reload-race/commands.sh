#!/bin/sh
# Print the unix-socket commands for the test: 30 cycles, each registering 8
# new tenants, reloading twice, then unregistering them. The second reload
# of each cycle is where the loaders race.
for c in $(seq 1 30); do
    for t in 1 2 3 4 5 6 7 8; do echo "register-tenant $((c * 10 + t)) tenant.yaml"; done
    echo reload-tenants
    echo reload-tenants
    for t in 1 2 3 4 5 6 7 8; do echo "unregister-tenant $((c * 10 + t))"; done
done
