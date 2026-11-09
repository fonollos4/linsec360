#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
tls_dir=${LINSEC_TLS_DIR:-"$repo_root/config/tls"}
cert_file=$tls_dir/fullchain.pem
key_file=$tls_dir/privkey.pem
hosts=${LINSEC_TLS_HOSTS:-"$(hostname -f 2>/dev/null || hostname),localhost,127.0.0.1"}
valid_days=${LINSEC_TLS_VALID_DAYS:-365}

case "$valid_days" in
    ''|*[!0-9]*)
        echo "LINSEC_TLS_VALID_DAYS must be a positive number" >&2
        exit 1
        ;;
esac
if [ "$valid_days" -lt 1 ] || [ "$valid_days" -gt 825 ]; then
    echo "LINSEC_TLS_VALID_DAYS must be between 1 and 825" >&2
    exit 1
fi

if [ -e "$cert_file" ] || [ -e "$key_file" ]; then
    echo "TLS certificate or key already exists; move them aside before generating a replacement" >&2
    exit 1
fi

command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required to generate the TLS certificate" >&2
    exit 1
}
command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to validate TLS hostnames" >&2
    exit 1
}

mkdir -p "$tls_dir"
chmod 700 "$tls_dir"
tmp_dir=$(mktemp -d "$tls_dir/.linsec-tls.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

python3 - "$hosts" "$tmp_dir/openssl.cnf" <<'PY'
import ipaddress
import re
import sys
from pathlib import Path

hosts = [host.strip() for host in sys.argv[1].split(",")]
if not hosts or any(not host for host in hosts):
    raise SystemExit("LINSEC_TLS_HOSTS must contain comma-separated DNS names or IP addresses")

dns_names = ["localhost"]
ip_addresses = ["127.0.0.1"]
for host in hosts:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host[2:] if host.startswith("*.") else host
        labels = name.split(".")
        label_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
        if "*" in host and not host.startswith("*."):
            raise SystemExit(f"invalid DNS name in LINSEC_TLS_HOSTS: {host}")
        if not all(label_pattern.fullmatch(label) for label in labels):
            raise SystemExit(f"invalid DNS name in LINSEC_TLS_HOSTS: {host}")
        if host not in dns_names:
            dns_names.append(host)
    else:
        value = str(address)
        if value not in ip_addresses:
            ip_addresses.append(value)

primary_name = dns_names[1] if len(dns_names) > 1 else dns_names[0]
lines = [
    "[req]",
    "prompt = no",
    "distinguished_name = subject",
    "x509_extensions = server_cert",
    "",
    "[subject]",
    f"CN = {primary_name}",
    "",
    "[server_cert]",
    "basicConstraints = critical,CA:FALSE",
    "keyUsage = critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage = serverAuth",
    "subjectAltName = @alt_names",
    "",
    "[alt_names]",
]
for index, name in enumerate(dns_names, 1):
    lines.append(f"DNS.{index} = {name}")
for index, address in enumerate(ip_addresses, 1):
    lines.append(f"IP.{index} = {address}")
Path(sys.argv[2]).write_text("\n".join(lines) + "\n", encoding="ascii")
PY

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -days "$valid_days" \
    -config "$tmp_dir/openssl.cnf" \
    -keyout "$tmp_dir/privkey.pem" \
    -out "$tmp_dir/fullchain.pem" \
    >/dev/null 2>&1

chmod 600 "$tmp_dir/privkey.pem"
chmod 644 "$tmp_dir/fullchain.pem"
mv "$tmp_dir/privkey.pem" "$key_file"
mv "$tmp_dir/fullchain.pem" "$cert_file"

echo "Self-signed TLS certificate created at $cert_file"
echo "Private key created at $key_file (mode 0600)"
echo "Certificate is self-signed; browsers will not trust it automatically."
