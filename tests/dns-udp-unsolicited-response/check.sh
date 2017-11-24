#! /bin/sh

# Check for 1 DNS request.
n=$(cat output/eve.json | jq -c 'select(.dns.type == "query")' | wc -l | xargs)
if [ ${n} -ne 1 ]; then
    exit 1
fi

# Check for 1 DNS response.
n=$(cat output/eve.json | jq -c 'select(.dns.type == "answer")' | wc -l | xargs)
if [ ${n} -ne 2 ]; then
    exit 1
fi

# Check for one alert.
n=$(cat output/eve.json | jq -c 'select(.event_type == "alert")' | wc -l | xargs)
if [ ${n} -ne 1 ]; then
    exit 1
fi

exit 0
