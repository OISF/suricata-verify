#! /bin/sh

tcp=$(cat eve.json | \
	  jq -c 'select(.event_type == "stats") | .stats.decoder.tcp')
test "${tcp}" = "7"
