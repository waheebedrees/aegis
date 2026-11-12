#!/usr/bin/env bash

set -euo pipefail

SPIRE_SERVER="spire-server"
COMPOSE_FILE="docker-compose.yml"
COMPOSE="docker compose -f $COMPOSE_FILE"

OUT_FILE="./deploy/dev/spire/x509pop/bootstrap.crt"


log (){
    echo "[bundle] $*"
}

ok=0
for i in $(seq 1 6); do
    # Check if the logs contain the success message
    if $COMPOSE logs $SPIRE_SERVER | grep -q "Starting Server APIs"; then 
        ok=1
        break
    fi
    sleep 1 
done
if [ "$ok" -ne 1 ]; then
    log "!! server never became ready"
    docker compose logs --tail=30 spire-server;
    exit 1
fi

# trust-bundle.sh
: > "$OUT_FILE"                     # ensure file exists, same inode
$COMPOSE exec -T "$SPIRE_SERVER" \
    /opt/spire/bin/spire-server bundle show -format pem > "$OUT_FILE"
log "ready"
