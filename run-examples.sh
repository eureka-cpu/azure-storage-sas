#!/bin/sh

set -eo pipefail

azurite --oauth basic --skipApiVersionCheck \
  --cert dev-certs/cert.pem --key dev-certs/key.pem &>/dev/null &
AZURITE_PID=$!

trap 'kill $AZURITE_PID 2>/dev/null' EXIT

sleep 1

for example in examples/*.rs; do
    cargo run --example "$(basename "$example" .rs)"
done
