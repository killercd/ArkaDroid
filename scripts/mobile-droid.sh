#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  mobile-droid.sh [--device SERIAL] set-proxy HOST:PORT
  mobile-droid.sh [--device SERIAL] set-invisible-proxy IPV4:PORT
  mobile-droid.sh [--device SERIAL] unset-proxy
  mobile-droid.sh [--device SERIAL] disable-invisible-proxy
  mobile-droid.sh [--device SERIAL] disable-proxies
  mobile-droid.sh --help

Commands:
  set-proxy                Set Android's global HTTP and HTTPS proxy settings.
  set-invisible-proxy      Redirect outbound IPv4 TCP ports 80 and 443 through
                           ArkaDroid's iptables chains. Requires adb root.
  unset-proxy              Clear Android's global HTTP and HTTPS proxy settings.
  disable-invisible-proxy  Remove ArkaDroid's iptables rules. Requires adb root.
  disable-proxies          Disable both proxy modes. Requires adb root for iptables.

Options:
  --device, -s SERIAL   Select an adb device.
  --help, -h            Show this help.
EOF
}

die() {
  local status="$1"
  shift
  printf 'Error: %s\n' "$*" >&2
  exit "$status"
}

configure_http_proxy() {
  adb "${adb_args[@]}" shell -T "sh -s -- '$1'" <<'ANDROID' || return
set -e
previous_http_proxy=$(settings get global http_proxy)
settings put global http_proxy "$1"
if ! settings put global https_proxy "$1"; then
  if [ "$previous_http_proxy" = null ]; then
    settings delete global http_proxy
  else
    settings put global http_proxy "$previous_http_proxy"
  fi
  exit 1
fi
ANDROID
  if [[ "$1" == :0 ]]; then
    printf 'Android proxy disabled.\n'
  else
    printf 'Android proxy configured at %s.\n' "$1"
  fi
}

configure_invisible_proxy() {
  local address="${1:-}"
  adb "${adb_args[@]}" root || return
  adb "${adb_args[@]}" wait-for-device || return
  adb "${adb_args[@]}" shell -T "sh -s -- '$address'" <<'ANDROID' || return
set -e
if [ "$(id -u)" != 0 ]; then
  echo 'Error: The Android device must support adb root.' >&2
  exit 1
fi

remove_jump() {
  while iptables -t nat -C "$@" 2>/dev/null; do
    iptables -t nat -D "$@" || return
  done
}

cleanup() {
  iptables -t nat -S OUTPUT >/dev/null || return
  remove_jump OUTPUT -p tcp --dport 80 -j ARKADROID_PROXY_OUT || return
  remove_jump OUTPUT -p tcp --dport 443 -j ARKADROID_PROXY_OUT || return
  remove_jump POSTROUTING -p tcp -j ARKADROID_PROXY_POST || return
  for chain in ARKADROID_PROXY_OUT ARKADROID_PROXY_POST; do
    if iptables -t nat -S "$chain" >/dev/null 2>&1; then
      iptables -t nat -F "$chain" || return
      iptables -t nat -X "$chain" || return
    fi
  done
}

cleanup
if [ -z "$1" ]; then
  exit 0
fi

trap cleanup EXIT
iptables -t nat -N ARKADROID_PROXY_OUT
iptables -t nat -N ARKADROID_PROXY_POST
iptables -t nat -A ARKADROID_PROXY_OUT -p tcp -j DNAT --to-destination "$1"
iptables -t nat -A ARKADROID_PROXY_POST -p tcp -j MASQUERADE
iptables -t nat -A OUTPUT -p tcp --dport 80 -j ARKADROID_PROXY_OUT
iptables -t nat -A OUTPUT -p tcp --dport 443 -j ARKADROID_PROXY_OUT
iptables -t nat -A POSTROUTING -p tcp -j ARKADROID_PROXY_POST
trap - EXIT
ANDROID
  if [[ -z "$address" ]]; then
    printf 'Invisible proxy disabled.\n'
  else
    printf 'Invisible proxy configured for IPv4 TCP ports 80 and 443 at %s.\n' "$address"
  fi
}

disable_proxies() {
  local status=0
  configure_http_proxy :0 || status=$?
  configure_invisible_proxy || status=$?
  return "$status"
}

validate_proxy_address() {
  local action="$1" address="$2"
  local host="${address%:*}" port="${address##*:}"
  local host_pattern='^([a-zA-Z0-9._-]+|\[[0-9a-fA-F:.]+\])$'
  [[ "$address" == *:* && "$host" =~ $host_pattern ]] ||
    die 2 'Use HOST:PORT or [IPv6]:PORT for the proxy address.'
  if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
    die 2 'The proxy port must be between 1 and 65535.'
  fi

  if [[ "$action" == set-invisible-proxy ]]; then
    local octet_pattern='(0|[1-9][0-9]{0,2})' octet
    local -a octets
    [[ "$host" =~ ^$octet_pattern\.$octet_pattern\.$octet_pattern\.$octet_pattern$ ]] ||
      die 2 'The invisible proxy requires an IPv4 address.'
    IFS=. read -r -a octets <<< "$host"
    for octet in "${octets[@]}"; do
      (( octet <= 255 )) || die 2 'The invisible proxy requires a valid IPv4 address.'
    done
  fi

  printf '%s:%d\n' "$host" "$((10#$port))"
}

adb_args=()
case "${1:-}" in
  --device|-s)
    [[ -n "${2:-}" && "$2" != -* ]] || die 2 'A device serial is required.'
    adb_args=(-s "$2")
    shift 2
    ;;
esac

case "${1:-}" in
  --help|-h)
    usage
    exit 0
    ;;
  set-proxy|set-invisible-proxy)
    [[ $# -eq 2 ]] || die 2 'Supply one proxy address in HOST:PORT format.'
    address="$(validate_proxy_address "$1" "$2")"
    ;;
  unset-proxy|disable-invisible-proxy|disable-proxies)
    [[ $# -eq 1 ]] || die 2 "The $1 command takes no proxy address."
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

command -v adb >/dev/null 2>&1 || die 1 'adb was not found in PATH.'

case "$1" in
  set-proxy) configure_http_proxy "$address" ;;
  set-invisible-proxy) configure_invisible_proxy "$address" ;;
  unset-proxy) configure_http_proxy :0 ;;
  disable-invisible-proxy) configure_invisible_proxy ;;
  disable-proxies) disable_proxies ;;
esac
