#! /bin/sh

tcp=$(cat output/eve.json | \
	  jq -c 'select(.event_type == "stats") | .stats.decoder.tcp')
test "${tcp}" = "7"
