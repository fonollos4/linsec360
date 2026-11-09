#!/bin/sh
set -eu

if ! grep -Eq '^[[:space:]]*Listen[[:space:]]+443([[:space:]]|$)' /etc/apache2/listen.conf; then
  printf '\nListen 443\n' >> /etc/apache2/listen.conf
fi
