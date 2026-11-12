#!/usr/bin/env bash


set -euo pipefail
SPIRE_PARENT_ID=$(docker compose  -f docker-compose.yml exec -T spire-server \
  /opt/spire/bin/spire-server agent list \
  | awk '/SPIFFE ID/ {print $4; exit}')

[[ -z "$SPIRE_PARENT_ID" ]] && { echo "no attested agent"; exit 1; }


create_or_update() {
  local spiffe_id="$1" uid="$2" ttl="$3"
  local entry_id
  entry_id=$(docker compose -f docker-compose.yml exec -T spire-server \
    /opt/spire/bin/spire-server entry show -spiffeID "$spiffe_id" 2>/dev/null \
    | awk -F': ' '/Entry ID/ {print $2; exit}')
  if [[ -z "$entry_id" ]]; then
    echo "→ create $spiffe_id (unix:uid:$uid)"
    docker compose -f docker-compose.yml  exec  -T spire-server /opt/spire/bin/spire-server entry create \
      -parentID "$SPIRE_PARENT_ID" \
      -spiffeID "$spiffe_id" \
      -selector "unix:uid:${uid}" \
      -x509SVIDTTL "$ttl"
  else
    echo "→ update $spiffe_id (entry $entry_id)"
    docker compose -f docker-compose.yml  exec -T spire-server /opt/spire/bin/spire-server entry update \
      -entryID "$entry_id" \
      -parentID "$SPIRE_PARENT_ID" \
      -spiffeID "$spiffe_id" \
      -selector "unix:uid:${uid}" \
      -x509SVIDTTL "$ttl"
  fi
}

create_or_update spiffe://$TRUST_DOMAIN/api-gateway 10010 "${TTL_OVERRIDE:-3600}"
create_or_update spiffe://$TRUST_DOMAIN/orchestrator     10001 "${TTL_OVERRIDE:-3600}"
create_or_update spiffe://$TRUST_DOMAIN/worker      10002 "${TTL_OVERRIDE:-3600}"
create_or_update spiffe://$TRUST_DOMAIN/llm-gateway 10020 "${TTL_OVERRIDE:-3600}"
create_or_update spiffe://$TRUST_DOMAIN/data-api    10030 "${TTL_OVERRIDE:-3600}"