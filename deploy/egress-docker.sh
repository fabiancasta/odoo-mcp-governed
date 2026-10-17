#!/usr/bin/env bash
# Let the MCP container reach Odoo and nothing else.
#
# By default a container can open connections anywhere: the internet, the
# LAN, and every service on the Docker host that listens on 0.0.0.0 — such as
# a PostgreSQL meant only for Odoo. If the MCP process were ever compromised,
# that is where it would go next. This script allows exactly one destination,
# Odoo's IP and port, plus replies to connections made *to* the container
# (the published MCP port), and drops everything else the container starts.
#
# Two chains, because there are two ways out:
#   DOCKER-USER  traffic forwarded to other machines (internet, LAN, a remote Odoo)
#   INPUT        traffic to the Docker host itself (host.docker.internal)
#
# Usage:  sudo deploy/egress-docker.sh <odoo-ip|host> <odoo-port> [network] [--allow-dns] [--dry-run]
#           odoo-ip     the address the container connects to, or "host" for an
#                       Odoo on the Docker host (host.docker.internal), which
#                       allows that port on any of the host's own addresses
#           network     docker network name (default odoo-mcp-governed_mcp_net)
#           --allow-dns also allow DNS (port 53), needed only when the Odoo URL
#                       is a hostname that is not in the container's /etc/hosts
# Undo:   sudo deploy/egress-docker.sh --remove
#
# Rules do not survive a reboot or a re-created network; persist them with
# your distribution's tooling and re-run after `docker compose down`.
set -euo pipefail

TAG="odoo-mcp-governed-egress"
DRY_RUN=0
ALLOW_DNS=0
ARGS=()
for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=1 ;;
    --allow-dns) ALLOW_DNS=1 ;;
    *) ARGS+=("${arg}") ;;
  esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

run() {
  if (( DRY_RUN )); then echo "iptables $*"; else iptables "$@"; fi
}

network_facts() {
  local net="$1"
  SUBNET=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "${net}")
  GATEWAY=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "${net}")
  local id
  id=$(docker network inspect -f '{{.Id}}' "${net}")
  BRIDGE=$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "${net}")
  [[ -n "${BRIDGE}" && "${BRIDGE}" != "<no value>" ]] || BRIDGE="br-${id:0:12}"
  [[ -n "${SUBNET}" && -n "${GATEWAY}" ]] || { echo "cannot read network ${net}" >&2; exit 1; }
}

remove_rules() {
  local chain
  for chain in DOCKER-USER INPUT; do
    while iptables -S "${chain}" | grep -q -- "${TAG}"; do
      local rule
      rule=$(iptables -S "${chain}" | grep -- "${TAG}" | head -n1 | sed 's/^-A /-D /')
      if (( DRY_RUN )); then echo "iptables ${rule}"; break; fi
      eval "iptables ${rule}"
    done
  done
}

if [[ "${1:-}" == "--remove" ]]; then
  remove_rules
  echo "removed ${TAG} rules"
  exit 0
fi

ODOO_IP="${1:?usage: $0 <odoo-ip|host> <odoo-port> [network] [--dry-run]}"
ODOO_PORT="${2:?usage: $0 <odoo-ip|host> <odoo-port> [network] [--dry-run]}"
NETWORK="${3:-odoo-mcp-governed_mcp_net}"
network_facts "${NETWORK}"
[[ "${ODOO_PORT}" =~ ^[0-9]+$ ]] || { echo "odoo-port must be a number" >&2; exit 1; }

echo "network ${NETWORK}: subnet ${SUBNET}, bridge ${BRIDGE}, gateway ${GATEWAY}"
echo "allowing only ${ODOO_IP}:${ODOO_PORT}"
(( DRY_RUN )) || remove_rules

C=(-m comment --comment "${TAG}")

# Rules are inserted at increasing positions, so the final order reads as
# written: replies first, then the one allowed destination, then the drop.
fwd=1 inp=1
add_fwd() { run -I DOCKER-USER "${fwd}" -s "${SUBNET}" "$@" "${C[@]}"; fwd=$((fwd + 1)); }
add_inp() { run -I INPUT "${inp}" -i "${BRIDGE}" "$@" "${C[@]}"; inp=$((inp + 1)); }

add_fwd -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
add_inp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
if (( ALLOW_DNS )); then
  for proto in udp tcp; do add_fwd -p "${proto}" --dport 53 -j RETURN; done
fi
if [[ "${ODOO_IP}" == "host" ]]; then
  # host.docker.internal resolves to docker0's address (often 172.17.0.1), not
  # this network's gateway, so match any address that belongs to the host.
  add_inp -p tcp --dport "${ODOO_PORT}" -m addrtype --dst-type LOCAL -j ACCEPT
else
  add_fwd -d "${ODOO_IP}" -p tcp --dport "${ODOO_PORT}" -j RETURN
fi
add_fwd -j DROP
add_inp -j DROP

if (( ! DRY_RUN )); then
  iptables -S DOCKER-USER | grep -- "${TAG}" || true
  iptables -S INPUT | grep -- "${TAG}" || true
fi
