#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "${script_dir}/.."

export PYTHONPATH="$PWD/backend${PYTHONPATH:+:$PYTHONPATH}"
export ARKADROID_PROXY_HOST="${DROIDBOARD_PROXY_HOST:-${ARKADROID_PROXY_HOST-127.0.0.1}}"

exec python3 -m flask --app droidboard.app:app run \
    --host "${DROIDBOARD_HOST-127.0.0.1}" \
    --port "${DROIDBOARD_PORT-5000}" \
    --no-reload --no-debugger --without-threads
