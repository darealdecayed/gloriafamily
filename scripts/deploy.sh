#!/bin/bash

echo "Deploying Solstice API..."

cd /root/solstice

npm run build

pm2 stop solstice-api 2>/dev/null || true
pm2 delete solstice-api 2>/dev/null || true

pm2 start dist/server.js --name solstice-api

echo "API deployed to port 9010"
echo "Configure Caddy with:"
echo "solstice-germany.opensourcedtech.com {"
echo "    reverse_proxy localhost:9010"
echo "    encode gzip"
echo "}"

pm2 save
