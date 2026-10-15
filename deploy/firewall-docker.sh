#!/usr/bin/env bash
# Restrict a published Docker port to one source address.
#
# Docker publishes ports by writing its own iptables NAT rules, which run
# before UFW's — so "ufw deny 8020" does nothing for a container. The
# DOCKER-USER chain is the one place Docker guarantees to consult first.
#
# Matching uses the ORIGINAL destination port (before Docker's DNAT), so only
# this one published port is affected — not every container that happens to
# listen on 8000 internally.
#
# Usage:  sudo deploy/firewall-docker.sh <allowed-source-ip> [published-port=8020]
# Undo:   sudo deploy/firewall-docker.sh --remove [published-port=8020]
# Rules do not survive a reboot; persist them with your distribution's tooling.
set -euo pipefail

TAG="odoo-mcp-governed"

remove_rules() {
  local port="$1"
  while iptables -S DOCKER-USER | grep -q -- "--comment \"\?${TAG}:${port}\"\?"; do
    local rule
    rule=$(iptables -S DOCKER-USER | grep -- "${TAG}:${port}" | head -n1 | sed 's/^-A /-D /')
    eval "iptables ${rule}"
  done
}

if [[ "${1:-}" == "--remove" ]]; then
  remove_rules "${2:-8020}"
  echo "removed rules for port ${2:-8020}"
  exit 0
fi

ALLOWED="${1:?usage: $0 <allowed-source-ip> [published-port]}"
PORT="${2:-8020}"

remove_rules "${PORT}"
iptables -I DOCKER-USER 1 -p tcp -m conntrack --ctorigdstport "${PORT}" --ctdir ORIGINAL \
  ! -s "${ALLOWED}" -j DROP -m comment --comment "${TAG}:${PORT}"
echo "port ${PORT}: only ${ALLOWED} may connect"
iptables -S DOCKER-USER | grep -- "${TAG}" || true
