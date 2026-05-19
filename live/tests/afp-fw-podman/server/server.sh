#! /bin/bash

set -e
set -x

echo "Starting tshark..."
tshark -i server -T json > /out/tshark-server.json &

echo "Starting caddy..."
cd /srv/www && exec caddy file-server browse
