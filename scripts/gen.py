import json
import pathlib
import yaml

ROOT = pathlib.Path(__file__).parent.parent
CFG = yaml.safe_load((ROOT / "agents.yaml").read_text(encoding="utf-8"))
TD = CFG["trust_domain"]
DEF = CFG.get("defaults", {})


class IndentDumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def spiffe(name):
    return f"spiffe://{TD}/{name}"


CONFIG_KEYS = {
    "model_id": "MODEL_ID",
    "model_version": "MODEL_VERSION",
    "system_prompt": "SYSTEM_PROMPT",
    "tools_json": "TOOLS_JSON",
    "policy_version": "POLICY_VERSION",
    "attest_interval_seconds": "ATTEST_INTERVAL_SECONDS",
    "target_url": "TARGET_URL",
    "log_level": "LOG_LEVEL",
}



def resolve(agent_cfg):
    out = {**DEF}
    for k in CONFIG_KEYS:
        if k in agent_cfg:
            out[k] = agent_cfg[k]
    if "ttl" in agent_cfg:
        out["ttl"] = agent_cfg["ttl"]
    return out

def service(name, cfg, resolved):
    port = resolved.get("port", 8443)
    peers = [
        {
            "id": spiffe(p),
            "host": p,
            "port": CFG["agents"][p].get("port", 8443),
        }
        for p in cfg["peers"]
    ]

    env = {
        "SPIFFE_ENDPOINT_SOCKET": "${SPIFFE_ENDPOINT_SOCKET}",
        "LISTEN_HOST": "0.0.0.0",
        "LISTEN_PORT": str(port),
    }
    for k in CONFIG_KEYS:
        if k in resolved:
            env[CONFIG_KEYS[k]] = str(resolved[k])

    env["HOME"] = f"/home/{name}"
    env["AGENT_ID"] = spiffe(name)
    env["PEERS"] = json.dumps(peers)

    return {
        "build": {
            "context": ".",
            "args": {
                "UID": str(cfg["uid"]),
                "GID": str(cfg["uid"]),
                "USERNAME": name,
            },
        },
        "image": f"agentic-identity/agent:{name}",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "labels": {"role": cfg["role"]},
        "volumes": [
            "spire-agent-socket:/tmp/spire-agent/public",
            "./src:/app/src",
            "/app/.venv",
        ],
        "environment": env,
    }


INIT_CMD = (
    "chown -R 1000:1000 "
    "/opt/spire/data/server "
    "/opt/spire/data/agent "
    "/tmp/spire-server/private "
    "/tmp/spire-agent/public"
)

INFRA = {
    "spire-init": {
        "image": "alpine:3.19",
        "command": ["sh", "-c", INIT_CMD],
        "volumes": [
            "spire-server-data:/opt/spire/data/server",
            "spire-agent-data:/opt/spire/data/agent",
            "spire-server-socket:/tmp/spire-server/private",
            "spire-agent-socket:/tmp/spire-agent/public",
        ],
    },
    "spire-server": {
        "image": "ghcr.io/spiffe/spire-server:1.14.4",
        "depends_on": {
            "spire-init": {"condition": "service_completed_successfully"}
        },
        "command": ["-config", "/opt/spire/conf/server/server.conf"],
        "hostname": "spire-server",
        "ports": [
            {"target": 8081, "published": 8081,
                "protocol": "tcp", "mode": "ingress"}
        ],
        "volumes": [
            "./spire/server.conf:/opt/spire/conf/server/server.conf:ro",
            "./spire/x509pop/ca.crt:/opt/spire/conf/server/x509pop-ca.crt:ro",
            "spire-server-data:/opt/spire/data/server",
            "spire-server-socket:/tmp/spire-server/private",
        ],
    },
    "spire-agent": {
        "image": "ghcr.io/spiffe/spire-agent:1.14.4",
        "hostname": "spire-agent",
        "pid": "host",
        "command": ["-config", "/opt/spire/conf/agent/agent.conf"],
        "volumes": [
            "./spire/agent.conf:/opt/spire/conf/agent/agent.conf:ro",
            "./spire/bootstrap.crt:/opt/spire/conf/agent/bootstrap.crt:ro",
            "./spire/x509pop/agent.crt:/etc/spire/agent.crt:ro",
            "./spire/x509pop/agent.key:/etc/spire/agent.key:ro",
            "spire-agent-data:/opt/spire/data/agent",
            "spire-agent-socket:/tmp/spire-agent/public",
            "/var/run/docker.sock:/var/run/docker.sock:ro",
        ],
        "depends_on": ["spire-server"],
    },
}

VOLUMES = {
    v: {"name": v}
    for v in (
        "spire-server-data",
        "spire-server-socket",
        "spire-agent-socket",
        "spire-agent-data",
    )
}

compose = {
    "services": {
        **INFRA,
        **{n: service(n, c, resolve(c)) for n, c in CFG["agents"].items()},
    },
    "volumes": VOLUMES,
}

# ASCII-only header. No em-dash.
header = "# AUTO-GENERATED from agents.yaml - do not edit by hand.\n"

yaml_text = yaml.dump(
    compose,
    Dumper=IndentDumper,
    sort_keys=False,
    default_flow_style=False,
    allow_unicode=False,   # any stray non-ASCII -> \uXXXX escape, still ASCII
    indent=2,
    width=100000,          # never auto-wrap long lines
)

(ROOT / "docker-compose.yml").write_text(
    header + yaml_text,
    encoding="utf-8",      # explicit; no cp1252 fallback
    newline="\n",          # LF on every platform
)



lines = [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "",
    'TTL_OVERRIDE=""',
    'while [[ $# -gt 0 ]]; do',
    '  case "$1" in',
    '    -ttl|--ttl) TTL_OVERRIDE="$2"; shift 2 ;;',
    '    *) echo "unknown argument: $1" >&2; exit 1 ;;',
    '  esac',
    'done',
    "",
    'PARENT_ID=$(docker compose exec -T spire-server \\',
    '  /opt/spire/bin/spire-server agent list \\',
    "  | awk '/SPIFFE ID/ {print $4; exit}')",
    '[[ -z "$PARENT_ID" ]] && { echo "no attested agent"; exit 1; }',
    "",
]

for name, cfg in CFG["agents"].items():
    resolved = resolve(cfg)
    ttl = resolved.get("ttl", 3600)
    lines += [
        f"# {name} (x509 ttl={ttl}s, override with -ttl N)",
        "docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \\",
        '  -parentID "$PARENT_ID" \\',
        f"  -spiffeID {spiffe(name)} \\",
        f"  -selector docker:label:role:{cfg['role']} \\",
        f"  -x509SVIDTTL ${{TTL_OVERRIDE:-{ttl}}}",
        "",
    ]
    
(ROOT / "register-entries.sh").write_text(
    "\n".join(lines),
    encoding="utf-8",
    newline="\n",
)
(ROOT / "register-entries.sh").chmod(0o755)

print(f"wrote docker-compose.yml ({len(CFG['agents'])} agents)")
print("wrote register-entries.sh")
