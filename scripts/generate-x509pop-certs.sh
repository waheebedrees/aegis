set -euo pipefail

export MSYS_NO_PATHCONV=1

OUT_DIR="./deploy/dev/spire/x509pop"

CA_KEY="${OUT_DIR}/ca.key"
CA_CERT="${OUT_DIR}/ca.crt"
AGENT_KEY="${OUT_DIR}/x509pop-agent.key"
AGENT_CERT="${OUT_DIR}/x509pop-agent.crt"
BUNDLE_PATH="${OUT_DIR}/bootstrap.crt"

FORCE="${FORCE:-0}"

log (){
    echo "[x509pop] $*"
}

certs_exist() {
    [ -f "${CA_KEY}" ] && [ -f "${CA_CERT}" ] && [ -f "${AGENT_KEY}" ] && [ -f "${AGENT_CERT}" ]
}

certs_valid() {
    openssl x509 -in "${CA_CERT}" -noout  2>/dev/null || return 1
    openssl x509 -in "${AGENT_CERT}" -noout  2>/dev/null || return 1
    openssl verify -CAfile "${CA_CERT}" "${AGENT_CERT}" >/dev/null 2>&1 || return 1

    return 0
}

if [ "${FORCE}" != "1" ] && certs_exist && certs_valid; then

    log "Certificates already exist and are valid in ${OUT_DIR}"
    log "Skipping generation. Use FORCE=1 to regenerate."
    exit 0
fi

log "generate output directory: ${OUT_DIR}"
mkdir -p "${OUT_DIR}"

ec_p_256 (){
    log "generate self-signed root CA (EC P-256, 3650 days).."

    openssl ecparam -genkey -name prime256v1 -noout -out "${CA_KEY}" 2>/dev/null
    openssl req -new -x509 \
        -key "${CA_KEY}" \
        -out "${CA_CERT}" \
        -days 3650 \
        -subj "/CN=aegis compose x509pop CA/O=aegis/OU=DEV" \
        -sha256


    log "generating agent CA (EC P-256, 365 days)..."
    openssl ecparam -genkey -name prime256v1 -noout -out "${AGENT_KEY}" 2>/dev/null

    AGENT_CSR="${OUT_DIR}/agent.csr"
    AGENT_EXT="${OUT_DIR}/agent_ext.cnf"

    openssl req -new \
        -key "${AGENT_KEY}" \
        -out "${AGENT_CSR}" \
        -subj "/CN=spire-agent/O=aegis/OU=Dev" \
        -sha256


    printf "keyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth" > "${AGENT_EXT}"

    openssl x509 -req \
        -in "${AGENT_CSR}" \
        -CA "${CA_CERT}" \
        -CAkey "${CA_KEY}" \
        -CAcreateserial \
        -out "${AGENT_CERT}" \
        -days 365 \
        -sha256 \
        -extfile "${AGENT_EXT}"


    rm -f "${OUT_DIR}/ca.srl"
    rm -f "$AGENT_CSR"
    rm -f "$AGENT_EXT"

    if  openssl verify -CAfile "${CA_CERT}" "${AGENT_CERT}" 2>/dev/null; then
        log "Agent certificate verified against CA."
    else
        log "ERROR: Agent certificate verification failed."
        exit 1
    fi

    log "Certificate Generation Complete."
    log "  CA cert:      ${CA_CERT}"
    log "  CA key:       ${CA_KEY}"
    log "  Agent cert:   ${AGENT_CERT}"
    log "  Agent key:    ${AGENT_KEY}"
}

rsa(){

    log "generate self-signed root CA (rsa, 3650 days).."

    openssl req -x509 \
        -newkey rsa:2048 -nodes \
        -keyout "${CA_KEY}"\
        -out "${CA_CERT}"\
        -days 3650 \
        -subj "/O=MyOrg/CN=SPIRE x509pop CA"

    log "generating agent CA (rsa, 365 days)..."
    AGENT_CSR="${OUT_DIR}/agent.csr"
    AGENT_EXT="${OUT_DIR}/agent_ext.cnf"
    printf "keyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth" > "${AGENT_EXT}"
	openssl req \
    -newkey rsa:2048 -nodes \
	-keyout  "${AGENT_KEY}" \
    -noout \
    -out "${AGENT_CSR}" \
	-subj "/O=MyOrg/CN=spire-agent-host"

    openssl req -new \
        -key "${AGENT_KEY}" \
        -out "${AGENT_CSR}" \
        -subj "/CN=spire-agent/O=aegis/OU=Dev" \
        -sha256

    openssl x509 -req \
        -in "${AGENT_CSR}" \
        -CA "${CA_CERT}" \
        -CAkey "${CA_KEY}" \
        -CAcreateserial \
        -out "${AGENT_CERT}" \
        -days 365 \
        -sha256 \
        -extfile "${AGENT_EXT}"


    rm -f "${OUT_DIR}/ca.srl"
    rm -f "$AGENT_CSR"
    rm -f "$AGENT_EXT"

    if  openssl verify -CAfile "${CA_CERT}" "${AGENT_CERT}" 2>/dev/null; then
        log "Agent certificate verified against CA."
    else
        log "ERROR: Agent certificate verification failed."
        exit 1
    fi

    openssl x509 -in "${AGENT_CERT}" -noout -text | grep -A1 "Key Usage"


    log "Certificate Generation Complete."
    log "  CA cert:      ${CA_CERT}"
    log "  CA key:       ${CA_KEY}"
    log "  Agent cert:   ${AGENT_CERT}"
    log "  Agent key:    ${AGENT_KEY}"

}

rsa