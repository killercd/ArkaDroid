#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/install-burp-ca-android.sh [HOST:PORT|PORT] [options]

Downloads a Burp-style proxy CA from http://burp/cert, converts it to the
Android system CA filename format, and installs it on the connected emulator.

Options:
  --proxy HOST:PORT   Proxy listener address. Default: 127.0.0.1:8080
  --device SERIAL     adb device serial to target.
  --name NAME         Local base filename. Default: burp-ca
  --keep-dir DIR      Keep generated files in DIR instead of a temp directory.
  --no-reboot         Do not reboot after installing the CA.
  --help             Show this help.

Examples:
  scripts/install-burp-ca-android.sh 8080
  scripts/install-burp-ca-android.sh 192.168.1.18:8080
  scripts/install-burp-ca-android.sh --proxy 127.0.0.1:8080 --device emulator-5554
EOF
}

proxy="127.0.0.1:8080"
device=""
name="burp-ca"
keep_dir=""
reboot_after=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy)
      proxy="${2:-}"
      shift 2
      ;;
    --device|-s)
      device="${2:-}"
      shift 2
      ;;
    --name)
      name="${2:-}"
      shift 2
      ;;
    --keep-dir)
      keep_dir="${2:-}"
      shift 2
      ;;
    --no-reboot)
      reboot_after=0
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *:*)
      proxy="$1"
      shift
      ;;
    ''|*[!0-9]*)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      proxy="127.0.0.1:$1"
      shift
      ;;
  esac
done

if [[ ! "$proxy" =~ ^[^:]+:[0-9]+$ ]]; then
  echo "Invalid proxy address: $proxy" >&2
  exit 2
fi

for bin in curl openssl adb; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Missing required command: $bin" >&2
    exit 1
  fi
done

adb_args=()
if [[ -n "$device" ]]; then
  adb_args=(-s "$device")
fi

if [[ -n "$keep_dir" ]]; then
  work_dir="$keep_dir"
  mkdir -p "$work_dir"
  cleanup() { :; }
else
  work_dir="$(mktemp -d -t burp-ca-android.XXXXXX)"
  cleanup() { rm -rf "$work_dir"; }
fi
trap cleanup EXIT

der_path="$work_dir/${name}.der"
pem_path="$work_dir/${name}.pem"

echo "[*] Downloading Burp CA through http://$proxy ..."
curl --fail --silent --show-error --location \
  --proxy "http://$proxy" \
  --output "$der_path" \
  "http://burp/cert"

if openssl x509 -inform DER -in "$der_path" -out "$pem_path" 2>/dev/null; then
  :
elif openssl x509 -inform PEM -in "$der_path" -out "$pem_path" 2>/dev/null; then
  :
else
  echo "Downloaded file is not a valid DER or PEM certificate: $der_path" >&2
  exit 1
fi

cert_hash="$(openssl x509 -inform PEM -subject_hash_old -in "$pem_path" | head -n 1 | tr -d '\r')"
if [[ ! "$cert_hash" =~ ^[0-9a-fA-F]+$ ]]; then
  echo "Unable to calculate Android subject_hash_old." >&2
  exit 1
fi

android_cert="$work_dir/${cert_hash}.0"
cp "$pem_path" "$android_cert"

echo "[*] Certificate subject:"
openssl x509 -in "$pem_path" -noout -subject -issuer -dates
echo "[*] Android certificate file: $(basename "$android_cert")"

echo "[*] Waiting for emulator/device ..."
adb "${adb_args[@]}" wait-for-device

echo "[*] Restarting adbd as root ..."
adb "${adb_args[@]}" root >/dev/null
adb "${adb_args[@]}" wait-for-device

echo "[*] Remounting system partition ..."
adb "${adb_args[@]}" remount >/dev/null

remote_path="/system/etc/security/cacerts/$(basename "$android_cert")"
echo "[*] Installing CA at $remote_path ..."
adb "${adb_args[@]}" push "$android_cert" "$remote_path" >/dev/null
adb "${adb_args[@]}" shell "chmod 644 '$remote_path' && chown root:root '$remote_path'"

echo "[*] Verifying installed CA ..."
adb "${adb_args[@]}" shell "ls -l '$remote_path'"

if [[ "$reboot_after" -eq 1 ]]; then
  echo "[*] Rebooting device so Android reloads system CAs ..."
  adb "${adb_args[@]}" reboot
else
  echo "[*] Installed without reboot. Reboot before relying on the CA."
fi

if [[ -n "$keep_dir" ]]; then
  echo "[*] Kept generated files in: $work_dir"
fi

echo "[+] Done."
