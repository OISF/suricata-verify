#! /bin/sh

# Test the flow record metadata.
test $(cat ./eve.json | \
    jq -c 'select(.event_type == "flow")' | \
    jq -c .metadata.flowbits[0]) == \"traffic/label/cli-http\"

# Test the alert record metadata.
test $(cat ./eve.json | \
    jq -c 'select(.event_type == "alert")' | \
    jq -c .metadata.flowbits[0]) == \"traffic/label/cli-http\"

# Test the netflow records. We should have 2 of those, so do a line
# count on netflow records with the required flowbit.
test $(cat ./eve.json | \
    jq -c 'select(.event_type == "netflow")' | \
    jq -c 'select(.metadata.flowbits[0] == "traffic/label/cli-http")' |\
    wc -l | xargs) -eq 2

