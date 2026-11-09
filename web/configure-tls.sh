#!/bin/sh
set -eu

tls_enabled=${LINSEC_TLS_ENABLED:-false}
environment=${LINSEC_ENVIRONMENT:-development}
https_port=${LINSEC_HTTPS_PORT:-8444}

case "$tls_enabled" in
    true|false) ;;
    *)
        echo "LINSEC_TLS_ENABLED must be true or false" >&2
        exit 1
        ;;
esac

case "$https_port" in
    ''|*[!0-9]*)
        echo "LINSEC_HTTPS_PORT must be a valid port number" >&2
        exit 1
        ;;
esac
if [ "$https_port" -lt 1 ] || [ "$https_port" -gt 65535 ]; then
    echo "LINSEC_HTTPS_PORT must be between 1 and 65535" >&2
    exit 1
fi

tls_config=/etc/nginx/conf.d/tls.conf
redirect_config=/etc/nginx/snippets/http-redirect.conf
rm -f "$tls_config"
: > "$redirect_config"

if [ "$tls_enabled" = "false" ]; then
    if [ "$environment" = "production" ]; then
        echo "TLS is required when LINSEC_ENVIRONMENT=production" >&2
        exit 1
    fi
    exit 0
fi

if [ ! -r /etc/nginx/certs/fullchain.pem ] || [ ! -r /etc/nginx/certs/privkey.pem ]; then
    echo "TLS is enabled but config/tls/fullchain.pem or privkey.pem is missing" >&2
    exit 1
fi

cat > "$tls_config" <<'NGINX'
server {
    listen 443 ssl;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:TLS:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    include /etc/nginx/snippets/linsec-locations.conf;
}
NGINX

cat > "$redirect_config" <<NGINX
return 308 https://\$host:${https_port}\$request_uri;
NGINX
