#!/bin/bash
set -euo pipefail

DEFAULT_MODE=--invisible

usage() {
  printf 'Uso: %s {start|stop} [--normal|--invisible]\n' "${0##*/}"
  printf 'Modalità predefinita: %s\n' "$DEFAULT_MODE"
}

if [[ $# -eq 1 && ( "$1" == --help || "$1" == -h ) ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 2
fi

case "${2-$DEFAULT_MODE}" in
  --normal)
    start_command=set-proxy
    stop_command=unset-proxy
    ;;
  --invisible)
    start_command=set-invisible-proxy
    stop_command=disable-invisible-proxy
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEVICE="${AUTOPTMOB_DEVICE:-emulator-5554}"
MOBILE_SCRIPT="$SCRIPT_DIR/scripts/mobile-droid.sh"

case "$1" in
  start)
    PROXY_PORT=8080
    if ! PROXY_IP="$(ifconfig wlo1 | awk '$1 == "inet" && !found {print $2; found=1}')"; then
      printf 'Impossibile leggere la configurazione di wlo1.\n' >&2
      exit 1
    fi
    if [[ -z "$PROXY_IP" ]]; then
      printf 'Nessun indirizzo IPv4 trovato su wlo1.\n' >&2
      exit 1
    fi
    "$SCRIPT_DIR/scripts/install-burp-ca-android.sh" --device "$DEVICE"
    if ! timeout 180 adb -s "$DEVICE" wait-for-device shell \
      'until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 1; done'; then
      printf 'Android non è pronto dopo il riavvio su %s.\n' "$DEVICE" >&2
      exit 1
    fi
    PROXY_ADDRESS="$PROXY_IP:$PROXY_PORT"
    if [[ "$start_command" == set-invisible-proxy ]]; then
      current_proxy="$(adb -s "$DEVICE" shell settings get global http_proxy)"
      if [[ "$current_proxy" == "$PROXY_ADDRESS" ]]; then
        "$MOBILE_SCRIPT" --device "$DEVICE" unset-proxy
      fi
    fi
    "$MOBILE_SCRIPT" --device "$DEVICE" "$start_command" "$PROXY_ADDRESS"
    ;;
  stop)
    "$MOBILE_SCRIPT" --device "$DEVICE" "$stop_command"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
