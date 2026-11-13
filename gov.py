"""gov.py — Aegis governance CLI.

Invoke as:
    python -m gov <subcommand> [flags]
or:
    python gov.py <subcommand> [flags]

═══════════════════════════════════════════════════════════════════════════
QUICK START — bootstrap a fresh cluster
═══════════════════════════════════════════════════════════════════════════

1. Generate all keys (one-shot):

       python -m gov gen-keys --dir keys --agents node-2

   Produces:
       keys/authority.{pub,seed}     signs the bundle (keep seed offline)
       keys/issuer.{pub,seed}        governor; issues capchain tokens
       keys/enrollment.{pub,seed}    signs enrollment receipts
       keys/node-2.{pub,seed}        agent workload key

2. Generate TLS material with SPIFFE URI SANs:

       python pki.py --out certs --force

3. Create governance.toml and populate it:

       python -m gov init \\
           --issuer-key     keys/issuer.pub \\
           --issuer-spiffe  spiffe://aegis-test/node-1 \\
           --enrollment-key keys/enrollment.pub \\
           --not-before     2026-01-01T00:00:00Z \\
           --expires-at     2026-04-01T00:00:00Z \\
           --out            config/governance.toml

       python -m gov add-pricing  --tool payments:read --base 1000

       python -m gov add-edge     --parent spiffe://aegis-test/node-1 \\
                                  --child  spiffe://aegis-test/node-2 \\
                                  --max-ttl 3600 --max-children 4 \\
                                  --ceiling-tools payments:read \\
                                  --ceiling-budget 1000000 \\
                                  --ceiling-audience spiffe://aegis-test/gateway

       python -m gov add-issuance --holder spiffe://aegis-test/node-2 \\
                                  --ttl 600 --max-depth 1 --model key_bound \\
                                  --scope-tools payments:read \\
                                  --scope-budget 1000000 \\
                                  --scope-audience spiffe://aegis-test/gateway

4. Validate and sign:

       python -m gov validate
       python -m gov sign --key keys/authority.seed --out config/governance.bundle

5. Generate node configs (one per node):

       python -m gov gen-node --name issuer --role issuer \\
           --spiffe-id spiffe://aegis-test/node-1 \\
           --listen 127.0.0.1:8444 \\
           --out config/node-issuer.toml

       python -m gov gen-node --name gateway --role gateway \\
           --spiffe-id spiffe://aegis-test/gateway \\
           --listen 127.0.0.1:8443 \\
           --peer "tool=127.0.0.1:8445@spiffe://aegis-test/tool" \\
           --out config/node-gateway.toml

       python -m gov gen-node --name node-2 --role agent \\
           --spiffe-id spiffe://aegis-test/node-2 \\
           --peer "gateway=127.0.0.1:8443@spiffe://aegis-test/gateway" \\
           --peer "parent=127.0.0.1:8444@spiffe://aegis-test/node-1" \\
           --out config/node-agent.toml


═══════════════════════════════════════════════════════════════════════════
DAY-2 WORKFLOW — after the cluster is running
═══════════════════════════════════════════════════════════════════════════

    Edit config/governance.toml by hand.
    Bump `version = N` at the top.
    Then:

       python -m gov validate
       python -m gov sign --key keys/authority.seed --out config/governance.bundle

    Copy the new bundle to each node, or let hot-reload pick it up.

    Add a new node:

       python -m gov gen-keys --dir keys --agents node-3
       python pki.py --out certs                      # include node-3
       python -m gov add-edge     --parent ... --child spiffe://aegis-test/node-3 ...
       python -m gov add-issuance --holder spiffe://aegis-test/node-3 ...
       # bump version, sign, gen-node --name node-3 --role agent

    Do NOT re-run `init --force` — it resets every edge, issuance, and
    pricing rule. init is a one-shot bootstrap.

═══════════════════════════════════════════════════════════════════════════
SUBCOMMANDS
═══════════════════════════════════════════════════════════════════════════

    gen-keys              Generate Ed25519 keypairs (authority, issuer,
                          enrollment, plus per-agent workload keys).
    init                  Create a fresh governance.toml (one-shot).
    gen-node              Generate a node-*.toml from a short flag set.

    show                  Summarize governance.toml.
    validate              Run the exact validator nodes run at load time.
    sign                  Compile governance.toml and sign the bundle.

    set-issuer-add        Add a trust root (issuer + first key).
    set-issuer-add-key    Add a key to an existing issuer.
    set-issuer-remove-key Remove a key from an issuer.
    set-issuer-remove     Remove an issuer entirely.

    set-enrollment-key    Pin the enrollment authority public key.
    set-enrollment-policy Set the enrollment ceiling / TTL / model.

    set-policy            Set max_depth, models, peer_bound_tools.
    set-default-pricing   Set the fallback price.

    add-edge / remove-edge
    add-issuance / remove-issuance
    add-pricing / remove-pricing

═══════════════════════════════════════════════════════════════════════════
FILES
═══════════════════════════════════════════════════════════════════════════

    config/governance.toml     Editable source. Written only by init and
                               the mutator subcommands. validate and sign
                               read it but never modify it.
    config/governance.bundle   Signed artifact produced by sign.
    config/node-*.toml         Per-node config. Generated by gen-node,
                               read by the node at startup. Hand-editable.
    keys/*.seed                Private keys. NEVER in a bundle, NEVER on
                               the wrong node, NEVER in git.
    keys/authority.seed        Signs the bundle. Keep offline / HSM.

═══════════════════════════════════════════════════════════════════════════
INVARIANTS
═══════════════════════════════════════════════════════════════════════════

  - Every node pins authority_keys in its node config. A bundle signed by
    any other key is refused at startup.
  - root_issuers == every issuer listed under [trust].roots. An edge whose
    parent is not a root will never be consulted for issuance coverage.
  - expires_at - not_before must be > 0 and <= 90 days.
  - Bump `version` on every edit. A node refuses a re-used version with a
    different digest ("equivocation: a different bundle also claims vN").
  - Every tool in any scope must have a pricing rule, or a `default` must
    be set.
  - A concrete holder in [[issuance]] needs an edge from a root whose
    ceiling contains the scope (checked by _cross_check at compile time).

═══════════════════════════════════════════════════════════════════════════
EXIT CODES
═══════════════════════════════════════════════════════════════════════════

    0    success
    1    runtime error (I/O failure, bad argument)
    2    validation error (schema or config error)
    130  interrupted (Ctrl-C)
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable

import libs.capchain.capchain as cc

from config.governance import (
    ConfigError,

    _PEER_NAME,
    compile_document,
    load_node_config,
    load_raw,
    load_seed,
    sign_bundle,
    sign_bundle_with_rotation,
    thumbprint,
)


log = logging.getLogger("aegis.gov")


class _CliFormatter(logging.Formatter):
    """INFO: bare message.  WARNING/ERROR: 'warning: ' / 'error: ' prefix."""

    _PREFIX = {"WARNING": "warning: ", "ERROR": "error: ", "CRITICAL": "error: "}

    def format(self, record: logging.LogRecord) -> str:
        return self._PREFIX.get(record.levelname, "") + record.getMessage()


def _setup_logging(verbose: bool = False) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_CliFormatter())
    log.handlers.clear()
    log.addHandler(handler)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.propagate = False


# ═════════════════════════════════════════════════════════════════════════
# Keys: encode / validate
# ═════════════════════════════════════════════════════════════════════════

KEY_BYTES = 32


def _require_32(raw: bytes) -> bytes:
    if len(raw) != KEY_BYTES:
        raise ValueError(
            f"ed25519 public key must be {KEY_BYTES} bytes, got {len(raw)}")
    return raw


def _encode(raw: bytes, scheme: str = "raw_b64") -> str:
    """Encode a 32-byte key as raw_b64, tagged1 ('base64:…'), or hex."""
    _require_32(raw)
    if scheme == "raw_b64":
        return cc.b64e(raw)
    if scheme == "tagged1":
        return "base64:" + cc.b64e(raw)
    if scheme == "hex":
        return raw.hex()
    raise ValueError(f"unknown scheme {scheme!r}")


# ═════════════════════════════════════════════════════════════════════════
# governance.toml: load / save
# ═════════════════════════════════════════════════════════════════════════

def _load(path: Path) -> dict:
    """Read governance.toml with keys still in wire (b64) form.

    Used by read-only commands (show, validate, sign): the on-disk form is
    exactly what compile_document expects.
    """
    try:
        return tomllib.loads(path.read_bytes().decode("utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"{path}: not found") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8") from None
    except OSError as exc:
        raise ConfigError(f"{path}: {exc}") from None


def _load_decoded(path: Path) -> dict:
    """Read governance.toml with every key decoded to raw bytes.

    Used by mutators whose _save() re-encodes every key: the decoded form
    lets us compare, append, and remove keys without base64 round-trips.
    """
    doc = _load(path)
    for r in doc.get("trust", {}).get("roots", []):
        r["keys"] = [load_raw(k) for k in r["keys"]]
    if "enrollment" in doc.get("trust", {}):
        doc["trust"]["enrollment"] = load_raw(doc["trust"]["enrollment"])
    return doc


# ═════════════════════════════════════════════════════════════════════════
# governance.toml: render / write
# ═════════════════════════════════════════════════════════════════════════

def _fmt_time(v: Any) -> str:
    """Render a timestamp as an unquoted TOML datetime, always UTC-Z."""
    if isinstance(v, dt.datetime):
        return v.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    s = str(v).strip()
    if s.endswith("Z"):
        return s
    if s.endswith("+00:00"):
        return s[:-6] + "Z"
    raise ConfigError(
        f"{v!r}: timestamps must be UTC (end with 'Z' or '+00:00')")


def _enc_scope(s: dict) -> str:
    parts = [
        'tools = [' + ", ".join(f'"{t}"' for t in s["tools"]) + ']',
        f'budget = {s["budget"]}',
        'audience = [' + ", ".join(f'"{a}"' for a in s["audience"]) + ']',
    ]
    if s.get("domains"):
        parts.append('domains = ['
                     + ", ".join(f'"{d}"' for d in s["domains"]) + ']')
    return "{ " + ", ".join(parts) + " }"


def _enc_cost(c: dict, *, with_tool: bool) -> str:
    parts = []
    if with_tool:
        parts.append(f'tool = "{c["tool"]}"')
    parts.append(f'base_micros = {c["base_micros"]}')
    if c.get("per_kib_micros"):
        parts.append(f'per_kib_micros = {c["per_kib_micros"]}')
    if c.get("max_micros") is not None:
        parts.append(f'max_micros = {c["max_micros"]}')
    return "{ " + ", ".join(parts) + " }"


def _render(doc: dict) -> str:
    """Serialize the decoded governance document as TOML."""
    L: list[str] = [
        "# Managed by scripts/gov.py — do not hand-edit.",
        "",
        f'version = {doc["version"]}',
        f'not_before = {_fmt_time(doc["not_before"])}',
        f'expires_at = {_fmt_time(doc["expires_at"])}',
        "",
        "[trust]",
        "roots = [",
    ]
    for r in doc["trust"]["roots"]:
        keys = ", ".join(f'"{_encode(k, "raw_b64")}"' for k in r["keys"])
        L.append(f'  {{ issuer = "{r["issuer"]}", keys = [{keys}] }},')
    L.append("]")
    if "enrollment" in doc["trust"]:
        L.append(
            f'enrollment = "{_encode(doc["trust"]["enrollment"], "raw_b64")}"')
    L.append("")

    p = doc["policy"]
    L += [
        "[policy]",
        f'max_depth = {p["max_depth"]}',
        'models = [' + ", ".join(f'"{m}"' for m in p["models"]) + ']',
        'peer_bound_tools = ['
        + ", ".join(f'"{t}"' for t in p.get("peer_bound_tools", [])) + ']',
        "edges = [",
    ]
    for e in p["edges"]:
        L.append(
            f'  {{ parent = "{e["parent"]}", child = "{e["child"]}", '
            f'max_ttl = {e["max_ttl"]}, '
            f'max_children = {e["max_children"]}, '
            f'ceiling = {_enc_scope(e["ceiling"])} }},'
        )
    L.append("]")
    L.append("")

    for r in doc.get("issuance", []):
        L += [
            "[[issuance]]",
            f'holder = "{r["holder"]}"',
            f'ttl = {r["ttl"]}',
            f'max_depth = {r["max_depth"]}',
            f'model = "{r["model"]}"',
            f'scope = {_enc_scope(r["scope"])}',
            "",
        ]

    if doc.get("enrollment"):
        e = doc["enrollment"]
        L += [
            "[enrollment]",
            f'may_enroll = "{e["may_enroll"]}"',
            f'ttl = {e["ttl"]}',
            f'model = "{e["model"]}"',
            f'ceiling = {_enc_scope(e["ceiling"])}',
            "",
        ]

    L.append("[pricing]")
    L.append("rules = [")
    for r in doc["pricing"]["rules"]:
        L.append(f'  {_enc_cost(r, with_tool=True)},')
    L.append("]")
    if doc["pricing"].get("default"):
        L.append(
            f'default = {_enc_cost(doc["pricing"]["default"], with_tool=False)}')
    L.append("")
    return "\n".join(L)


def _save(path: Path, doc: dict) -> None:
    """Atomically write governance.toml, preserving prior file mode."""
    text = _render(doc)
    old_mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(old_mode)
    tmp.replace(path)


# ═════════════════════════════════════════════════════════════════════════
# Key generation
# ═════════════════════════════════════════════════════════════════════════

def _generate_keypair(pub_path: Path, seed_path: Path) -> None:
    """Write a fresh Ed25519 keypair. Seed is chmod 0600; pub is 0644."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    seed = k.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = k.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_bytes(seed)
    seed_path.chmod(0o600)
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.write_bytes(pub)
    pub_path.chmod(0o644)


# ═════════════════════════════════════════════════════════════════════════
# Argument helpers
# ═════════════════════════════════════════════════════════════════════════

def _split(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def _scope_from_args(args: argparse.Namespace, prefix: str) -> dict:
    s = {
        "tools":    _split(getattr(args, f"{prefix}_tools") or ""),
        "budget":   getattr(args, f"{prefix}_budget"),
        "audience": _split(getattr(args, f"{prefix}_audience") or ""),
    }
    if d := getattr(args, f"{prefix}_domains", None):
        s["domains"] = _split(d)
    return s


def _add_scope_args(sp: argparse.ArgumentParser, prefix: str) -> None:
    sp.add_argument(f"--{prefix}-tools", required=True,
                    help="comma-separated tool ids")
    sp.add_argument(f"--{prefix}-budget", type=int, required=True,
                    help="budget in micros")
    sp.add_argument(f"--{prefix}-audience", required=True,
                    help="comma-separated audience spiffe ids")
    sp.add_argument(f"--{prefix}-domains", default="",
                    help="optional comma-separated domains")


# ═════════════════════════════════════════════════════════════════════════
# Command: gen-keys
# ═════════════════════════════════════════════════════════════════════════

def cmd_gen_keys(args: argparse.Namespace) -> int:
    """Generate authority, issuer, enrollment, and per-agent keypairs.

    The authority seed signs the governance bundle and must stay offline.
    The issuer seed is the capchain governor; it lives on the issuer only.
    The enrollment seed signs receipts; it lives on the issuer only.
    Agent seeds live on their respective agents.

    Refuses to overwrite unless --force.
    """
    base = Path(args.dir)
    pairs = [
        (base / "authority.pub",  base / "authority.seed"),
        (base / "issuer.pub",     base / "issuer.seed"),
        (base / "enrollment.pub", base / "enrollment.seed"),
    ]
    for name in _split(args.agents):
        pairs.append((base / f"{name}.pub", base / f"{name}.seed"))

    for pub, seed in pairs:
        if (pub.exists() or seed.exists()) and not args.force:
            log.error("%s or %s exists (pass --force to regenerate)",
                      pub, seed)
            return 2

    for pub, seed in pairs:
        _generate_keypair(pub, seed)
        log.info("  → generated %s", pub)
        log.info("  → generated %s  (private)", seed)
    return 0


# ═════════════════════════════════════════════════════════════════════════
# Command: init
# ═════════════════════════════════════════════════════════════════════════

def cmd_init(args: argparse.Namespace) -> int:
    """Create a fresh governance.toml.

    One-shot bootstrap. Once the file exists, edit it by hand and re-sign.
    Running ``init --force`` overwrites every edge, issuance, and pricing
    rule previously added.
    """
    path = Path(args.out)
    if path.exists() and not args.force:
        log.error("%s exists (pass --force to overwrite)", path)
        return 2

    try:
        issuer_raw = load_raw(Path(args.issuer_key))
        enroll_raw = load_raw(Path(args.enrollment_key))
    except (ValueError, OSError) as exc:
        log.error("key error: %s", exc)
        return 2

    doc = {
        "version": 1,
        "not_before": args.not_before,
        "expires_at": args.expires_at,
        "trust": {
            "roots": [{"issuer": args.issuer_spiffe, "keys": [issuer_raw]}],
            "enrollment": enroll_raw,
        },
        "policy": {
            "max_depth": 1,
            "models": ["key_bound"],
            "peer_bound_tools": [],
            "edges": [],
        },
        "issuance": [],
        "enrollment": None,
        "pricing": {"rules": [], "default": {"base_micros": 1000}},
    }
    _save(path, doc)
    log.info("wrote %s", path)
    return 0


# ═════════════════════════════════════════════════════════════════════════
# Command: gen-node
# ═════════════════════════════════════════════════════════════════════════

_REQUIRED_PEERS: dict[str, set[str]] = {
    "gateway": {"tool"},
    "issuer":  set(),
    "agent":   {"gateway", "parent"},
    "tool":    {"gateway"},
}


def _parse_peer(spec: str) -> tuple[str, dict]:
    """Parse ``NAME=HOST:PORT@SPIFFE_ID`` → (name, {host, port, spiffe_id})."""
    if "=" not in spec:
        raise ValueError(f"expected NAME=HOST:PORT@SPIFFE_ID, got {spec!r}")
    name, rest = spec.split("=", 1)
    if "@" not in rest:
        raise ValueError(f"peer {name}: missing @SPIFFE_ID")
    hostport, spiffe = rest.rsplit("@", 1)
    if ":" not in hostport:
        raise ValueError(f"peer {name}: expected HOST:PORT, got {hostport!r}")
    host, port_s = hostport.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        raise ValueError(f"peer {name}: port must be int, got {port_s!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"peer {name}: port {port} out of range")
    if not spiffe.startswith("spiffe://"):
        raise ValueError(f"peer {name}: spiffe_id must start with spiffe://")
    if not _PEER_NAME.fullmatch(name):
        raise ValueError(
            f"peer {name}: name must match [a-z][a-z0-9._-]{{0,31}}")
    return name, {"host": host, "port": port, "spiffe_id": spiffe}


def _render_node_toml(d: dict) -> str:
    """Serialize a node-config dict as TOML."""
    p = lambda v: Path(v).as_posix()
    L = [
        "# Generated by `gov.py gen-node` — safe to edit, never regenerated.",
        "",
        f'role        = "{d["role"]}"',
        f'spiffe_id   = "{d["spiffe_id"]}"',
        f'environment = "{d["environment"]}"',
        "",
        "[tls]",
        f'cert_file     = "{p(d["tls"]["cert_file"])}"',
        f'key_file      = "{p(d["tls"]["key_file"])}"',
        f'ca_file       = "{p(d["tls"]["ca_file"])}"',
        'trust_domains = ['
        + ", ".join(f'"{x}"' for x in d["tls"]["trust_domains"]) + "]",
        "",
        "[governance]",
        f'bundle_file             = "{p(d["governance"]["bundle_file"])}"',
        f'state_file              = "{p(d["governance"]["state_file"])}"',
        'authority_keys          = ['
        + ", ".join(f'"{k}"' for k in d["governance"]["authority_keys"]) + "]",
        f'reload_interval_seconds = {d["governance"]["reload_interval_seconds"]}',
        f'min_version             = {d["governance"]["min_version"]}',
        "",
    ]
    if "listen" in d:
        L += ["[listen]",
              f'host = "{d["listen"]["host"]}"',
              f'port = {d["listen"]["port"]}', ""]
    if "stores" in d:
        L += ["[stores]", f'backend = "{d["stores"]["backend"]}"', ""]
    for name in sorted(d.get("peers", {})):
        e = d["peers"][name]
        L += [f"[peers.{name}]",
              f'host      = "{e["host"]}"',
              f'port      = {e["port"]}',
              f'spiffe_id = "{e["spiffe_id"]}"', ""]
    if "key" in d:
        L += ["[key]", f'seed_file = "{p(d["key"]["seed_file"])}"', ""]
    if "issuer" in d:
        L += ["[issuer]",
              f'root_seed_file = "{p(d["issuer"]["root_seed_file"])}"', ""]
    return "\n".join(L)


def cmd_gen_node(args: argparse.Namespace) -> int:
    """Generate a node-*.toml from a short flag set.

    Derived defaults:
      cert / key          certs/{name}.crt / certs/{name}.key
      state_file          state/{name}.governance.state
      workload seed       keys/{name}.seed          (agent only)
      governor seed       keys/issuer.seed          (issuer only)

    Everything is overridable. Peers are validated against _REQUIRED_PEERS
    before the file is written, so a gateway without a 'tool' peer fails
    here rather than at node startup.
    """
    name = args.name
    out = Path(args.out or f"config/node-{name}.toml")
    if out.exists() and not args.force:
        log.error("%s exists (pass --force)", out)
        return 2

    role = args.role
    cert = Path(args.cert) if args.cert else Path("certs") / f"{name}.crt"
    key = Path(args.key) if args.key else Path("certs") / f"{name}.key"
    ca = Path(args.ca)
    bundle = Path(args.bundle)
    state = Path(args.state) if args.state else \
        Path("state") / f"{name}.governance.state"

    if "://" not in args.spiffe_id:
        log.error("--spiffe-id: bad format %r", args.spiffe_id)
        return 2
    domain = args.spiffe_id.split("://", 1)[1].split("/", 1)[0]

    authority = Path(args.authority)
    if not authority.exists():
        log.error("--authority %s: not found", authority)
        return 2
    try:
        authority_b64 = cc.b64e(load_raw(authority))
    except (ValueError, OSError) as exc:
        log.error("--authority: %s", exc)
        return 2

    peer_map: dict[str, dict] = {}
    for spec in args.peer or []:
        try:
            pname, peer = _parse_peer(spec)
        except ValueError as exc:
            log.error("--peer: %s", exc)
            return 2
        peer_map[pname] = peer

    missing = _REQUIRED_PEERS[role] - set(peer_map)
    if missing:
        log.error("role %r requires --peer for %s", role, sorted(missing))
        return 2

    listen = None
    if role in ("gateway", "issuer", "tool"):
        if not args.listen:
            log.error("role %r requires --listen HOST:PORT", role)
            return 2
        host, port_s = args.listen.rsplit(":", 1)
        try:
            listen = (host, int(port_s))
        except ValueError:
            log.error("--listen %r: bad port", args.listen)
            return 2

    stores = args.stores_backend if role in ("gateway", "issuer") else None

    workload_seed = (Path(args.workload_seed) if args.workload_seed
                     else Path("keys") / f"{name}.seed")
    governor_seed = (Path(args.governor_seed) if args.governor_seed
                     else Path("keys") / "issuer.seed")

    if args.gen_seed:
        if role != "agent":
            log.error("--gen-seed only applies to --role agent")
            return 2
        pub = workload_seed.with_suffix(".pub")
        if (pub.exists() or workload_seed.exists()) and not args.force:
            log.error("%s or %s exists (pass --force)", pub, workload_seed)
            return 2
        _generate_keypair(pub, workload_seed)
        log.info("  → generated %s", pub)
        log.info("  → generated %s  (private, agent only)", workload_seed)

    doc: dict = {
        "role": role,
        "spiffe_id": args.spiffe_id,
        "environment": args.environment,
        "tls": {
            "cert_file": cert,
            "key_file": key,
            "ca_file": ca,
            "trust_domains": [domain],
        },
        "governance": {
            "bundle_file": bundle,
            "state_file": state,
            "authority_keys": [authority_b64],
            "reload_interval_seconds": 30,
            "min_version": 1,
        },
    }
    if listen:
        doc["listen"] = {"host": listen[0], "port": listen[1]}
    if stores:
        doc["stores"] = {"backend": stores}
    if peer_map:
        doc["peers"] = peer_map
    if role == "agent":
        doc["key"] = {"seed_file": workload_seed}
    if role == "issuer":
        doc["issuer"] = {"root_seed_file": governor_seed}

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_render_node_toml(doc), encoding="utf-8")
    log.info("✓ wrote %s", out)

    try:
        load_node_config(out)
        log.info("✓ validated")
    except ConfigError as exc:
        log.warning("not yet loadable: %s", exc)
        log.warning(
            "  (normal during bootstrapping — generate certs and sign the "
            "bundle, then re-check)")
    return 0


# ═════════════════════════════════════════════════════════════════════════
# Commands: show / validate / sign
# ═════════════════════════════════════════════════════════════════════════

def cmd_show(args: argparse.Namespace) -> int:
    """Summarize governance.toml. Read-only — does not modify the file."""
    doc = _load(Path(args.file))
    for r in doc["trust"]["roots"]:
        r["keys"] = [load_raw(k) for k in r["keys"]]
    if "enrollment" in doc["trust"]:
        doc["trust"]["enrollment"] = load_raw(doc["trust"]["enrollment"])

    for r in doc["trust"]["roots"]:
        log.info("issuer      = %s", r["issuer"])
        for k in r["keys"]:
            log.info("  key       = %s  (sha256=%s..)",
                     _encode(k, "raw_b64"), thumbprint(k)[:16])
    if "enrollment" in doc["trust"]:
        k = doc["trust"]["enrollment"]
        log.info("enrollment  = %s  (sha256=%s..)",
                 _encode(k, "raw_b64"), thumbprint(k)[:16])
    log.info("max_depth   = %s", doc["policy"]["max_depth"])
    log.info("models      = %s", doc["policy"]["models"])
    log.info("edges       = %d", len(doc["policy"]["edges"]))
    log.info("issuance    = %d rule(s)", len(doc.get("issuance", [])))
    log.info("enrollment  = %s", "set" if doc.get("enrollment") else "unset")
    log.info("pricing     = %d rule(s), default=%s",
             len(doc["pricing"]["rules"]),
             "yes" if doc["pricing"].get("default") else "no")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Compile governance.toml using the exact validator nodes run.

    A file that validates here will parse at node startup, assuming it is
    signed by a pinned authority key.
    """
    try:
        compile_document(_load(Path(args.file)))
    except ConfigError as exc:
        log.error("invalid: %s", exc)
        return 2
    log.info("ok")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Compile governance.toml and sign it with the authority key.

    The output bundle is node-loadable and ready for GovernanceLoader.
    Does not modify governance.toml.
    """
    try:
        doc = compile_document(_load(Path(args.file)))
    except ConfigError as exc:
        log.error("invalid: %s", exc)
        return 2

    try:
        current = cc.CapChainKey.from_seed(load_seed(Path(args.key)))
        nxt = (cc.CapChainKey.from_seed(load_seed(Path(args.next_key)))
               if args.next_key else None)
    except (OSError, ValueError) as exc:
        log.error("key error: %s", exc)
        return 2

    raw = (sign_bundle_with_rotation(doc, current, nxt)
           if nxt is not None else sign_bundle(doc, current))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(raw)
    tmp.replace(out)

    log.info("✓ signed → %s (%d bytes)%s",
             out, len(raw), " [rotation]" if nxt is not None else "")
    return 0


# ═════════════════════════════════════════════════════════════════════════
# Commands: issuers
# ═════════════════════════════════════════════════════════════════════════

def cmd_set_issuer(args: argparse.Namespace) -> int:
    """Manage the trust-root set (``[trust].roots``)."""
    doc = _load_decoded(Path(args.file))
    roots = doc["trust"]["roots"]

    if args.action == "add":
        if any(r["issuer"] == args.spiffe for r in roots):
            log.error("issuer %s exists", args.spiffe)
            return 2
        roots.append({"issuer": args.spiffe, "keys": [load_raw(args.key)]})
    elif args.action == "add-key":
        target = next((r for r in roots if r["issuer"] == args.spiffe), None)
        if target is None:
            log.error("issuer %s not found", args.spiffe)
            return 2
        raw = load_raw(args.key)
        if raw in target["keys"]:
            log.error("key already present")
            return 2
        target["keys"].append(raw)
    elif args.action == "remove-key":
        target = next((r for r in roots if r["issuer"] == args.spiffe), None)
        if target is None:
            log.error("issuer %s not found", args.spiffe)
            return 2
        raw = load_raw(args.key)
        if raw not in target["keys"]:
            log.error("key not present")
            return 2
        target["keys"].remove(raw)
        if not target["keys"]:
            roots.remove(target)
    elif args.action == "remove":
        before = len(roots)
        roots[:] = [r for r in roots if r["issuer"] != args.spiffe]
        if len(roots) == before:
            log.error("issuer %s not found", args.spiffe)
            return 2

    _save(Path(args.file), doc)
    log.info("✓ %s %s", args.action, args.spiffe)
    return 0


def cmd_set_enrollment_key(args: argparse.Namespace) -> int:
    """Pin the enrollment authority public key in ``[trust].enrollment``."""
    doc = _load_decoded(Path(args.file))
    doc["trust"]["enrollment"] = load_raw(args.key)
    _save(Path(args.file), doc)
    log.info("✓ enrollment key pinned")
    return 0


def cmd_set_enrollment_policy(args: argparse.Namespace) -> int:
    """Set the ``[enrollment]`` constraint block.

    Requires the enrollment key to be pinned first: policy without an
    authority is unverifiable at node startup.
    """
    doc = _load_decoded(Path(args.file))
    if "enrollment" not in doc["trust"]:
        log.error("pin the key first: set-enrollment-key")
        return 2
    doc["enrollment"] = {
        "may_enroll": args.may_enroll,
        "ttl": args.ttl,
        "model": args.model,
        "ceiling": _scope_from_args(args, "ceiling"),
    }
    _save(Path(args.file), doc)
    log.info("✓ enrollment policy set")
    return 0


def cmd_set_policy(args: argparse.Namespace) -> int:
    """Update ``[policy]`` scalars: max_depth, models, peer_bound_tools.

    Edges are managed separately (add-edge / remove-edge).
    """
    doc = _load_decoded(Path(args.file))
    p = doc["policy"]
    if args.max_depth is not None:
        p["max_depth"] = args.max_depth
    if args.models is not None:
        p["models"] = _split(args.models)
    if args.peer_bound_tools is not None:
        p["peer_bound_tools"] = _split(args.peer_bound_tools)
    _save(Path(args.file), doc)
    log.info("✓ policy updated")
    return 0


# ═════════════════════════════════════════════════════════════════════════
# Commands: edges
# ═════════════════════════════════════════════════════════════════════════

def cmd_add_edge(args: argparse.Namespace) -> int:
    """Append a delegation edge ``(parent → child, ceiling, max_ttl)``.

    Order matters: ``Policy.edge()`` returns the *first* match. If a
    wildcard edge is added before a specific one, the wildcard wins.
    """
    doc = _load_decoded(Path(args.file))
    if any(e["parent"] == args.parent and e["child"] == args.child
           for e in doc["policy"]["edges"]):
        log.error("edge already exists")
        return 2
    doc["policy"]["edges"].append({
        "parent": args.parent,
        "child": args.child,
        "max_ttl": args.max_ttl,
        "max_children": args.max_children,
        "ceiling": _scope_from_args(args, "ceiling"),
    })
    _save(Path(args.file), doc)
    log.info("✓ added edge %s → %s", args.parent, args.child)
    return 0


def cmd_remove_edge(args: argparse.Namespace) -> int:
    """Remove an edge identified by (parent, child)."""
    doc = _load_decoded(Path(args.file))
    before = len(doc["policy"]["edges"])
    doc["policy"]["edges"] = [
        e for e in doc["policy"]["edges"]
        if not (e["parent"] == args.parent and e["child"] == args.child)
    ]
    if len(doc["policy"]["edges"]) == before:
        log.error("edge not found")
        return 2
    _save(Path(args.file), doc)
    log.info("✓ removed edge %s → %s", args.parent, args.child)
    return 0


# ═════════════════════════════════════════════════════════════════════════
# Commands: issuance
# ═════════════════════════════════════════════════════════════════════════

def cmd_add_issuance(args: argparse.Namespace) -> int:
    """Append an issuance rule ``[[issuance]]``.

    A concrete holder must be covered by an edge from a root issuer whose
    ceiling contains the requested scope; _cross_check enforces this at
    compile time. A pattern holder (``…/*``) is exempt and re-validated
    at issue time.
    """
    doc = _load_decoded(Path(args.file))
    if any(r["holder"] == args.holder for r in doc.get("issuance", [])):
        log.error("issuance for %s exists", args.holder)
        return 2
    doc.setdefault("issuance", []).append({
        "holder": args.holder,
        "ttl": args.ttl,
        "max_depth": args.max_depth,
        "model": args.model,
        "scope": _scope_from_args(args, "scope"),
    })
    _save(Path(args.file), doc)
    log.info("✓ added issuance for %s", args.holder)
    return 0


def cmd_remove_issuance(args: argparse.Namespace) -> int:
    """Remove every issuance rule whose holder matches exactly."""
    doc = _load_decoded(Path(args.file))
    before = len(doc.get("issuance", []))
    doc["issuance"] = [r for r in doc.get("issuance", [])
                       if r["holder"] != args.holder]
    if len(doc["issuance"]) == before:
        log.error("issuance for %s not found", args.holder)
        return 2
    _save(Path(args.file), doc)
    log.info("✓ removed issuance for %s", args.holder)
    return 0


# ═════════════════════════════════════════════════════════════════════════
# Commands: pricing
# ═════════════════════════════════════════════════════════════════════════

def cmd_add_pricing(args: argparse.Namespace) -> int:
    """Append an exact or ``namespace:*`` pricing rule."""
    doc = _load_decoded(Path(args.file))
    if any(r["tool"] == args.tool for r in doc["pricing"]["rules"]):
        log.error("pricing for %s exists", args.tool)
        return 2
    doc["pricing"]["rules"].append({
        "tool": args.tool,
        "base_micros": args.base,
        "per_kib_micros": args.per_kib,
        "max_micros": args.max,
    })
    _save(Path(args.file), doc)
    log.info("✓ added pricing for %s", args.tool)
    return 0


def cmd_remove_pricing(args: argparse.Namespace) -> int:
    """Remove a pricing rule by exact tool name."""
    doc = _load_decoded(Path(args.file))
    before = len(doc["pricing"]["rules"])
    doc["pricing"]["rules"] = [r for r in doc["pricing"]["rules"]
                               if r["tool"] != args.tool]
    if len(doc["pricing"]["rules"]) == before:
        log.error("pricing for %s not found", args.tool)
        return 2
    _save(Path(args.file), doc)
    log.info("✓ removed pricing for %s", args.tool)
    return 0


def cmd_set_default_pricing(args: argparse.Namespace) -> int:
    """Set the fallback price.

    Required if any scope permits ``*`` (any tool). Also covers any tool
    not matched by an exact or namespace rule.
    """
    doc = _load_decoded(Path(args.file))
    doc["pricing"]["default"] = {
        "base_micros": args.base,
        "per_kib_micros": args.per_kib,
        "max_micros": args.max,
    }
    _save(Path(args.file), doc)
    log.info("✓ default pricing set")
    return 0


# ═════════════════════════════════════════════════════════════════════════
# argparse / main
# ═════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="gov.py")
    ap.add_argument("--file", default="config/governance.toml",
                    help="path to governance.toml")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="debug logging")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # ─ init ─
    sp = sub.add_parser("init", help="create a fresh governance.toml")
    sp.add_argument("--issuer-key", required=True,
                    help="issuer PUBLIC key (governor)")
    sp.add_argument("--issuer-spiffe", required=True)
    sp.add_argument("--enrollment-key", required=True,
                    help="enrollment PUBLIC key")
    sp.add_argument("--not-before", required=True)
    sp.add_argument("--expires-at", required=True)
    sp.add_argument("--out", default="config/governance.toml")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_init)

    # ─ gen-keys ─
    sp = sub.add_parser("gen-keys", help="generate Ed25519 keypairs")
    sp.add_argument("--dir", default="keys")
    sp.add_argument("--agents", default="",
                    help="comma-separated agent names, e.g. node-2,node-3")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_gen_keys)

    # ─ gen-node ─
    sp = sub.add_parser("gen-node", help="generate a node-*.toml")
    sp.add_argument("--name", required=True,
                    help="short name (defaults for paths and peer names)")
    sp.add_argument("--role", required=True,
                    choices=["gateway", "issuer", "agent", "tool"])
    sp.add_argument("--spiffe-id", required=True)
    sp.add_argument("--environment", default="development",
                    choices=["development", "production"])
    sp.add_argument("--listen",
                    help="HOST:PORT (required for gateway/issuer/tool)")
    sp.add_argument("--peer", action="append", default=[],
                    metavar="NAME=HOST:PORT@SPIFFE_ID")
    sp.add_argument("--authority", default="keys/authority.pub")
    sp.add_argument("--bundle", default="config/governance.bundle")
    sp.add_argument("--cert", help="default: certs/{name}.crt")
    sp.add_argument("--key", help="default: certs/{name}.key")
    sp.add_argument("--ca", default="certs/ca.crt")
    sp.add_argument("--state", help="default: state/{name}.governance.state")
    sp.add_argument("--workload-seed",
                    help="agent only (default: keys/{name}.seed)")
    sp.add_argument("--governor-seed",
                    help="issuer only (default: keys/issuer.seed)")
    sp.add_argument("--stores-backend", default="memory",
                    choices=["memory", "redis", "database"])
    sp.add_argument("--gen-seed", action="store_true",
                    help="agent: generate workload keypair if missing")
    sp.add_argument("--out", help="default: config/node-{name}.toml")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_gen_node)

    # ─ read-only ─
    sub.add_parser("show", help="summarize governance.toml") \
        .set_defaults(func=cmd_show)
    sub.add_parser("validate", help="validate governance.toml") \
        .set_defaults(func=cmd_validate)

    # ─ sign ─
    sp = sub.add_parser("sign", help="compile and sign the bundle")
    sp.add_argument("--key", required=True,
                    help="path to current authority SEED")
    sp.add_argument("--next-key", default=None,
                    help="path to next authority SEED (rotation)")
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_sign)

    # ─ issuers ─
    for action in ("add", "add-key", "remove-key", "remove"):
        sp = sub.add_parser(f"set-issuer-{action}")
        sp.add_argument("spiffe")
        if action in ("add", "add-key", "remove-key"):
            sp.add_argument("--key", required=True)
        sp.set_defaults(func=cmd_set_issuer, action=action)

    # ─ enrollment ─
    sp = sub.add_parser("set-enrollment-key")
    sp.add_argument("--key", required=True)
    sp.set_defaults(func=cmd_set_enrollment_key)

    sp = sub.add_parser("set-enrollment-policy")
    sp.add_argument("--may-enroll", required=True)
    sp.add_argument("--ttl", type=int, required=True)
    sp.add_argument("--model", default="key_bound")
    _add_scope_args(sp, "ceiling")
    sp.set_defaults(func=cmd_set_enrollment_policy)

    # ─ policy ─
    sp = sub.add_parser("set-policy")
    sp.add_argument("--max-depth", type=int)
    sp.add_argument("--models")
    sp.add_argument("--peer-bound-tools")
    sp.set_defaults(func=cmd_set_policy)

    # ─ edges ─
    sp = sub.add_parser("add-edge")
    sp.add_argument("--parent", required=True)
    sp.add_argument("--child", required=True)
    sp.add_argument("--max-ttl", type=int, required=True)
    sp.add_argument("--max-children", type=int, default=32)
    _add_scope_args(sp, "ceiling")
    sp.set_defaults(func=cmd_add_edge)

    sp = sub.add_parser("remove-edge")
    sp.add_argument("--parent", required=True)
    sp.add_argument("--child", required=True)
    sp.set_defaults(func=cmd_remove_edge)

    # ─ issuance ─
    sp = sub.add_parser("add-issuance")
    sp.add_argument("--holder", required=True)
    sp.add_argument("--ttl", type=int, required=True)
    sp.add_argument("--max-depth", type=int, default=1)
    sp.add_argument("--model", default="key_bound")
    _add_scope_args(sp, "scope")
    sp.set_defaults(func=cmd_add_issuance)

    sp = sub.add_parser("remove-issuance")
    sp.add_argument("--holder", required=True)
    sp.set_defaults(func=cmd_remove_issuance)

    # ─ pricing ─
    sp = sub.add_parser("add-pricing")
    sp.add_argument("--tool", required=True)
    sp.add_argument("--base", type=int, required=True)
    sp.add_argument("--per-kib", type=int, default=0)
    sp.add_argument("--max", type=int, default=None)
    sp.set_defaults(func=cmd_add_pricing)

    sp = sub.add_parser("remove-pricing")
    sp.add_argument("--tool", required=True)
    sp.set_defaults(func=cmd_remove_pricing)

    sp = sub.add_parser("set-default-pricing")
    sp.add_argument("--base", type=int, required=True)
    sp.add_argument("--per-kib", type=int, default=0)
    sp.add_argument("--max", type=int, default=None)
    sp.set_defaults(func=cmd_set_default_pricing)

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = _build_parser()
    args = ap.parse_args(argv)
    _setup_logging(args.verbose)

    try:
        return args.func(args)
    except ConfigError as exc:
        log.error("%s", exc)
        return 2
    except ValueError as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())