
.PHONY: help gen build certs volume bundle up down nuke restart \
        logs status list entries fingerprint  run docker dc sh 

ENV ?= dev
SHELL        := /bin/bash
SPIRE_SERVER := /opt/spire/bin/spire-server
REG_SCRIPT ?= ./scripts/register-entries.sh

COMPOSE := docker compose -f docker-compose.yml 

# Load .env if present (exports all vars to recipes)
-include .env
export


# Docker volume holding the agent's SVID and bootstrap bundle
VOL_AGENT ?= $(AGENT_DATA_VOLUME)

# Generator and registration script paths

# Show available targets with their descriptions
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Regenerate docker-compose.yml and register-entries.sh from agents.yaml
gen:
	python $(GEN_SCRIPT)

# Build per-agent images (manager, worker, ...)
build:
	$(COMPOSE) build

# Generate x509pop CA and agent certificate for node attestation
certs:
	@bash ./scripts/generate-x509pop-certs.sh

# Ensure the agent data volume exists
volume:
	@docker volume inspect $(VOL_AGENT) >/dev/null 2>&1 \
	  || docker volume create $(VOL_AGENT) >/dev/null
	@echo "   volume $(VOL_AGENT) ready"

# Fetch trust bundle from the server and copy it into the agent data volume
bundle:
	@bash ./scripts/trust-bundle.sh 


up: volume
	$(COMPOSE) up -d spire-server volumes-init
	@bash ./scripts/trust-bundle.sh
	$(COMPOSE) up -d spire-agent orchestrator worker
	./$(REG_SCRIPT)

	$(COMPOSE) logs -f spire-server spire-agent


	
# Stop all services, keep volumes
down:
	$(COMPOSE) down

# Stop all services and remove volumes — full reset
# Restart the SPIRE agent
restart:
	$(COMPOSE) restart spire-agent

# Follow logs for spire-server and spire-agent
logs:
	$(COMPOSE) logs -f spire-server spire-agent


log-nodes:
	$(COMPOSE) logs -f worker orchestrator spire-server spire-agent

# Show running containers
status:
	$(COMPOSE) ps

# Print the agent's x509pop fingerprint
fingerprint:
	@$(COMPOSE) logs spire-agent 2>&1 | grep -o 'x509pop/[a-f0-9]*' | head -1 | cut -d/ -f2

# List attested agents
list:
	$(COMPOSE) exec spire-server $(SPIRE_SERVER) agent list

# Show all registration entries
entries:
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) entry show


register: 
	./$(REG_SCRIPT)

# Remove generated x509pop CA and agent certs
clean:
	$(COMPOSE) down -v 

worker-bash:
	$(COMPOSE) exec worker bash

	
manager-bash:
	$(COMPOSE) exec orchestrator bash

ids:
	$(COMPOSE) exec manager id
	$(COMPOSE) exec worker id


watch:
	
	$(COMPOSE) up --watch orchestrator worker


run: clean build certs up 


sh:
	@$(COMPOSE) exec $(SRC) bash


push:
	gh push 
