"""gov.py — Aegis governance CLI.

Invoke as:
    python -m gov <subcommand> [flags]
or:
    python gov.py <subcommand> [flags]
or (installed):
    aegis <subcommand> [flags]

═══════════════════════════════════════════════════════════════════════════
QUICK START — bootstrap a fresh cluster
═══════════════════════════════════════════════════════════════════════════

1. Generate all keys (one-shot):

       aegis gen-keys --dir keys --agents node-2

   Produces:
       keys/authority.{pub,seed}     signs the bundle (keep seed offline)
       keys/issuer.{pub,seed}        governor; issues capchain tokens
       keys/enrollment.{pub,seed}    signs enrollment receipts
       keys/node-2.{pub,seed}        agent workload key

2. Generate TLS material with SPIFFE URI SANs:

       python pki.py --out certs --force

3. Create governance.toml and populate it:

       aegis init \\
           --issuer-key     keys/issuer.pub \\
           --issuer-spiffe  spiffe://aegis-test/node-1 \\
           --enrollment-key keys/enrollment.pub \\
           --not-before     2026-01-01T00:00:00Z \\
           --expires-at     2026-04-01T00:00:00Z \\
           --out            config/governance.toml

       aegis add-pricing  --tool payments:read --base 1000

       aegis add-edge     --parent spiffe://aegis-test/node-1 \\
                                  --child  spiffe://aegis-test/node-2 \\
                                  --max-ttl 3600 --max-children 4 \\
                                  --ceiling-tools payments:read \\
                                  --ceiling-budget 1000000 \\
                                  --ceiling-audience spiffe://aegis-test/gateway

       aegis add-issuance --holder spiffe://aegis-test/node-2 \\
                                  --ttl 600 --max-depth 1 --model key_bound \\
                                  --scope-tools payments:read \\
                                  --scope-budget 1000000 \\
                                  --scope-audience spiffe://aegis-test/gateway

4. Validate and sign:

       aegis validate
       aegis sign --key keys/authority.seed --out config/governance.bundle

5. Generate node configs (one per node):

       aegis gen-node --name issuer --role issuer \\
           --spiffe-id spiffe://aegis-test/node-1 \\
           --listen 127.0.0.1:8444 \\
           --out config/node-issuer.toml

       aegis gen-node --name gateway --role gateway \\
           --spiffe-id spiffe://aegis-test/gateway \\
           --listen 127.0.0.1:8443 \\
           --peer "tool=127.0.0.1:8445@spiffe://aegis-test/tool" \\
           --out config/node-gateway.toml

       aegis gen-node --name node-2 --role agent \\
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

       aegis validate
       aegis sign --key keys/authority.seed --out config/governance.bundle

    Copy the new bundle to each node, or let hot-reload pick it up.

    Add a new node:

       aegis gen-keys --dir keys --agents node-3
       python pki.py --out certs                      # include node-3
       aegis add-edge     --parent ... --child spiffe://aegis-test/node-3 ...
       aegis add-issuance --holder spiffe://aegis-test/node-3 ...
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
    2    validation error (schema or config error, or argparse usage)
    130  interrupted (Ctrl-C)
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import tomllib
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax
from rich.table import Table
from typer import BadParameter

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

# Cross-platform exclusive file lock (POSIX: fcntl, Windows: msvcrt).
if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


__version__ = "0.2.0"


# ═════════════════════════════════════════════════════════════════════════
# App / consoles / state
# ═════════════════════════════════════════════════════════════════════════

app = typer.Typer(
    name="aegis",
    help="Aegis governance CLI — bootstrap, edit, validate, sign.",
    rich_markup_mode="rich",
    add_completion=False,
)
stdout = Console()
stderr = Console(stderr=True)


class _State:
    file: Path = Path("config/governance.toml")


state = _State()


# ═════════════════════════════════════════════════════════════════════════
# Error / output helpers
# ═════════════════════════════════════════════════════════════════════════

def _die(msg: str, code: int = 2) -> typer.Exit:
    stderr.print(f"[bold red]error:[/bold red] {escape(msg)}")
    return typer.Exit(code)


def _warn(msg: str) -> None:
    stderr.print(f"[yellow]warning:[/yellow] {escape(msg)}")


def _ok(msg: str) -> None:
    stdout.print(f"[green]✓[/green] {escape(msg)}")


# ═════════════════════════════════════════════════════════════════════════
# Validators
# ═════════════════════════════════════════════════════════════════════════

KEY_BYTES = 32
_SPIFFE_RE = re.compile(r"^spiffe://[a-z0-9.-]+(/[A-Za-z0-9._*-]+)+$")


def _check_spiffe(s: str) -> str:
    if not _SPIFFE_RE.fullmatch(s):
        raise BadParameter(f"invalid SPIFFE ID: {s!r}")
    return s


def _require_32(raw: bytes) -> bytes:
    if len(raw) != KEY_BYTES:
        raise ValueError(f"ed25519 public key must be {KEY_BYTES} bytes, got {len(raw)}")
    return raw


def _encode(raw: bytes, scheme: str = "raw_b64") -> str:
    _require_32(raw)
    if scheme == "raw_b64":
        return cc.b64e(raw)
    if scheme == "tagged1":
        return "base64:" + cc.b64e(raw)
    if scheme == "hex":
        return raw.hex()
    raise ValueError(f"unknown scheme {scheme!r}")


def _split(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


# ═════════════════════════════════════════════════════════════════════════
# Load / decode
# ═════════════════════════════════════════════════════════════════════════

def _load(path: Path) -> dict:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        raise ConfigError(f"{path}: not found") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8") from None
    except OSError as exc:
        raise ConfigError(f"{path}: {exc}") from None


def _load_decoded(path: Path) -> dict:
    doc = _load(path)
    for r in doc.get("trust", {}).get("roots", []):
        r["keys"] = [load_raw(k) for k in r.get("keys", [])]
    if "enrollment" in doc.get("trust", {}):
        doc["trust"]["enrollment"] = load_raw(doc["trust"]["enrollment"])
    return doc


# ═════════════════════════════════════════════════════════════════════════
# Render / save
# ═════════════════════════════════════════════════════════════════════════

def _fmt_time(v: Any) -> str:
    if isinstance(v, dt.datetime):
        if v.tzinfo is None:
            raise ConfigError(f"{v!r}: timestamps must be timezone-aware")
        return v.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    s = str(v).strip()
    if s.endswith("Z"):
        return s
    if s.endswith("+00:00"):
        return s[:-6] + "Z"
    raise ConfigError(f"{v!r}: timestamps must be UTC (end with 'Z' or '+00:00')")


def _show_time(v: Any) -> str:
    """Best-effort ISO-8601 rendering for display-only fields."""
    if v is None:
        return "?"
    try:
        return _fmt_time(v)
    except ConfigError:
        return str(v)


def _enc_scope(s: dict) -> str:
    parts = [
        "tools = [" + ", ".join(f'"{t}"' for t in s["tools"]) + "]",
        f'budget = {s["budget"]}',
        "audience = [" + ", ".join(f'"{a}"' for a in s["audience"]) + "]",
    ]
    if s.get("domains"):
        parts.append("domains = [" + ", ".join(f'"{d}"' for d in s["domains"]) + "]")
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
    L: list[str] = [
        "# Managed by gov.py. Comments are not preserved across mutations.",
        "",
        f'version = {doc["version"]}',
        f"not_before = {_fmt_time(doc['not_before'])}",
        f"expires_at = {_fmt_time(doc['expires_at'])}",
        "",
        "[trust]",
        "roots = [",
    ]
    for r in doc["trust"]["roots"]:
        keys = ", ".join(f'"{_encode(k, "raw_b64")}"' for k in r["keys"])
        L.append(f'  {{ issuer = "{r["issuer"]}", keys = [{keys}] }},')
    L.append("]")
    if "enrollment" in doc["trust"]:
        L.append(f'enrollment = "{_encode(doc["trust"]["enrollment"], "raw_b64")}"')
    L.append("")

    p = doc["policy"]
    L += [
        "[policy]",
        f'max_depth = {p["max_depth"]}',
        "models = [" + ", ".join(f'"{m}"' for m in p["models"]) + "]",
        "peer_bound_tools = ["
        + ", ".join(f'"{t}"' for t in p.get("peer_bound_tools", []))
        + "]",
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
        L.append(f"  {_enc_cost(r, with_tool=True)},")
    L.append("]")
    if doc["pricing"].get("default"):
        L.append(f'default = {_enc_cost(doc["pricing"]["default"], with_tool=False)}')
    L.append("")
    return "\n".join(L)


def _lock_exclusive(fh) -> None:
    if sys.platform == "win32":
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)


def _unlock(fh) -> None:
    if sys.platform == "win32":
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _atomic_write(path: Path, text: str) -> None:
    old_mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("w") as lock:
        _lock_exclusive(lock)
        try:
            tmp = path.with_name(path.name + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            tmp.chmod(old_mode)
            tmp.replace(path)
        finally:
            _unlock(lock)


def _commit(path: Path, doc: dict, *, dry_run: bool, validate: bool = True) -> None:
    text = _render(doc)
    if validate:
        try:
            compile_document(tomllib.loads(text))
        except ConfigError as exc:
            raise _die(f"refusing to write invalid config: {exc}", 2)
    if dry_run:
        stdout.print(Syntax(text, "toml", theme="monokai", line_numbers=False))
        stdout.print(f"[dim]dry-run — would write {path}[/dim]")
        return
    _atomic_write(path, text)


def _scope(tools: str, budget: int, audience: str, domains: str = "") -> dict:
    s = {"tools": _split(tools), "budget": budget, "audience": _split(audience)}
    if domains:
        s["domains"] = _split(domains)
    return s


# ═════════════════════════════════════════════════════════════════════════
# Key generation
# ═════════════════════════════════════════════════════════════════════════

def _generate_keypair(pub_path: Path, seed_path: Path) -> None:
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
# Callback
# ═════════════════════════════════════════════════════════════════════════

def _version_callback(value: bool) -> None:
    if value:
        stdout.print(f"aegis {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _main_callback(
    ctx: typer.Context,
    file: Annotated[Path, typer.Option("--file", help="Path to governance.toml")] = Path(
        "config/governance.toml"
    ),
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Verbose diagnostics")] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = False,
) -> None:
    """Global options."""
    if ctx.invoked_subcommand is None and not version:
        stdout.print(ctx.get_help())
        raise typer.Exit()
    state.file = file
    if verbose:
        stderr.print(f"[dim]file={file}[/dim]")


# ═════════════════════════════════════════════════════════════════════════
# gen-keys
# ═════════════════════════════════════════════════════════════════════════

@app.command("gen-keys")
def gen_keys(
    directory: Annotated[Path, typer.Option("--dir", help="Key directory")] = Path("keys"),
    agents: Annotated[str, typer.Option("--agents", help="Comma-separated agent names")] = "",
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing keys")] = False,
    strict: Annotated[
        bool, typer.Option("--strict", help="Abort if any key already exists")
    ] = False,
) -> None:
    """Generate Ed25519 keypairs (authority, issuer, enrollment, agents)."""
    pairs = [
        ("authority", directory / "authority.pub", directory / "authority.seed"),
        ("issuer", directory / "issuer.pub", directory / "issuer.seed"),
        ("enrollment", directory / "enrollment.pub", directory / "enrollment.seed"),
    ]
    for name in _split(agents):
        pairs.append((name, directory / f"{name}.pub", directory / f"{name}.seed"))

    for name, pub, seed in pairs:
        exists = pub.exists() or seed.exists()
        if exists and not force:
            if strict:
                raise _die(f"{name}: key exists (drop --strict or pass --force)")
            stdout.print(f"[dim]  skip {name} (exists)[/dim]")
            continue
        _generate_keypair(pub, seed)
        _ok(f"generated {pub}")
        _ok(f"generated {seed}  (private)")


# ═════════════════════════════════════════════════════════════════════════
# init
# ═════════════════════════════════════════════════════════════════════════

@app.command("init")
def init(
    issuer_key: Annotated[Path, typer.Option("--issuer-key", help="Issuer PUBLIC key")],
    issuer_spiffe: Annotated[str, typer.Option("--issuer-spiffe")],
    enrollment_key: Annotated[Path, typer.Option("--enrollment-key", help="Enrollment PUBLIC key")],
    not_before: Annotated[str, typer.Option("--not-before", help="ISO-8601 UTC")],
    expires_at: Annotated[str, typer.Option("--expires-at", help="ISO-8601 UTC")],
    out: Annotated[Path, typer.Option("--out")] = Path("config/governance.toml"),
    force: Annotated[bool, typer.Option("--force")] = False,
) -> None:
    """Create a fresh governance.toml (one-shot bootstrap)."""
    _check_spiffe(issuer_spiffe)
    if out.exists() and not force:
        raise _die(f"{out} exists (pass --force to overwrite)")
    try:
        issuer_raw = load_raw(issuer_key)
        enroll_raw = load_raw(enrollment_key)
    except (ValueError, OSError) as exc:
        raise _die(f"key error: {exc}")

    doc = {
        "version": 1,
        "not_before": not_before,
        "expires_at": expires_at,
        "trust": {
            "roots": [{"issuer": issuer_spiffe, "keys": [issuer_raw]}],
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
    _commit(out, doc, dry_run=False)
    _ok(f"wrote {out}")


# ═════════════════════════════════════════════════════════════════════════
# gen-node
# ═════════════════════════════════════════════════════════════════════════

_REQUIRED_PEERS: dict[str, set[str]] = {
    "gateway": {"tool"},
    "issuer": set(),
    "agent": {"gateway", "parent"},
    "tool": {"gateway"},
}


def _parse_peer(spec: str) -> tuple[str, dict]:
    if "=" not in spec:
        raise BadParameter(f"--peer: expected NAME=HOST:PORT@SPIFFE_ID, got {spec!r}")
    name, rest = spec.split("=", 1)
    if "@" not in rest:
        raise BadParameter(f"--peer {name}: missing @SPIFFE_ID")
    hostport, spiffe = rest.rsplit("@", 1)
    if ":" not in hostport:
        raise BadParameter(f"--peer {name}: expected HOST:PORT, got {hostport!r}")
    host, port_s = hostport.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        raise BadParameter(f"--peer {name}: port must be int, got {port_s!r}")
    if not (1 <= port <= 65535):
        raise BadParameter(f"--peer {name}: port {port} out of range")
    _check_spiffe(spiffe)
    if not _PEER_NAME.fullmatch(name):
        raise BadParameter(f"--peer {name}: name must match [a-z][a-z0-9._-]{{0,31}}")
    return name, {"host": host, "port": port, "spiffe_id": spiffe}


def _parse_listen(spec: str) -> tuple[str, int]:
    if ":" not in spec:
        raise BadParameter(f"--listen: expected HOST:PORT, got {spec!r}")
    host, port_s = spec.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        raise BadParameter(f"--listen: port must be int, got {port_s!r}")
    if not (1 <= port <= 65535):
        raise BadParameter(f"--listen: port {port} out of range")
    if not host:
        raise BadParameter("--listen: empty host")
    return host, port


def _render_node_toml(d: dict) -> str:
    p = lambda v: Path(v).as_posix()  # noqa: E731
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
        + ", ".join(f'"{x}"' for x in d["tls"]["trust_domains"])
        + "]",
        "",
        "[governance]",
        f'bundle_file             = "{p(d["governance"]["bundle_file"])}"',
        f'state_file              = "{p(d["governance"]["state_file"])}"',
        'authority_keys          = ['
        + ", ".join(f'"{k}"' for k in d["governance"]["authority_keys"])
        + "]",
        f'reload_interval_seconds = {d["governance"]["reload_interval_seconds"]}',
        f'min_version             = {d["governance"]["min_version"]}',
        "",
    ]
    if "listen" in d:
        L += ["[listen]", f'host = "{d["listen"]["host"]}"', f'port = {d["listen"]["port"]}', ""]
    if "stores" in d:
        L += ["[stores]", f'backend = "{d["stores"]["backend"]}"', ""]
    for name in sorted(d.get("peers", {})):
        e = d["peers"][name]
        L += [
            f"[peers.{name}]",
            f'host      = "{e["host"]}"',
            f"port      = {e['port']}",
            f'spiffe_id = "{e["spiffe_id"]}"',
            "",
        ]
    if "key" in d:
        L += ["[key]", f'seed_file = "{p(d["key"]["seed_file"])}"', ""]
    if "issuer" in d:
        L += ["[issuer]", f'root_seed_file = "{p(d["issuer"]["root_seed_file"])}"', ""]
    return "\n".join(L)


@app.command("gen-node")
def gen_node(
    name: Annotated[str, typer.Option("--name")],
    role: Annotated[str, typer.Option("--role", help="gateway | issuer | agent | tool")],
    spiffe_id: Annotated[str, typer.Option("--spiffe-id")],
    environment: Annotated[str, typer.Option("--environment")] = "development",
    listen: Annotated[str | None, typer.Option("--listen", help="HOST:PORT")] = None,
    peer: Annotated[list[str], typer.Option("--peer", help="NAME=HOST:PORT@SPIFFE_ID (repeatable)")] = [],
    authority: Annotated[Path, typer.Option("--authority")] = Path("keys/authority.pub"),
    bundle: Annotated[Path, typer.Option("--bundle")] = Path("config/governance.bundle"),
    cert: Annotated[Path | None, typer.Option("--cert")] = None,
    key: Annotated[Path | None, typer.Option("--key")] = None,
    ca: Annotated[Path, typer.Option("--ca")] = Path("certs/ca.crt"),
    state_file: Annotated[Path | None, typer.Option("--state")] = None,
    workload_seed: Annotated[Path | None, typer.Option("--workload-seed")] = None,
    governor_seed: Annotated[Path | None, typer.Option("--governor-seed")] = None,
    stores_backend: Annotated[str, typer.Option("--stores-backend")] = "memory",
    gen_seed: Annotated[bool, typer.Option("--gen-seed")] = False,
    out: Annotated[Path | None, typer.Option("--out")] = None,
    force: Annotated[bool, typer.Option("--force")] = False,
) -> None:
    """Generate a node-*.toml from a short flag set."""
    if role not in _REQUIRED_PEERS:
        raise BadParameter(f"unknown role {role!r}")
    if environment not in ("development", "production"):
        raise BadParameter(f"unknown environment {environment!r}")
    if stores_backend not in ("memory", "redis", "database"):
        raise BadParameter(f"unknown stores backend {stores_backend!r}")
    _check_spiffe(spiffe_id)
    domain = spiffe_id[len("spiffe://"):].split("/", 1)[0]

    out = out or Path(f"config/node-{name}.toml")
    if out.exists() and not force:
        raise _die(f"{out} exists (pass --force)")

    cert = cert or Path("certs") / f"{name}.crt"
    key = key or Path("certs") / f"{name}.key"
    state_file = state_file or Path("state") / f"{name}.governance.state"

    if not authority.exists():
        raise _die(f"--authority {authority}: not found")
    try:
        authority_b64 = cc.b64e(load_raw(authority))
    except (ValueError, OSError) as exc:
        raise _die(f"--authority: {exc}")

    peer_map: dict[str, dict] = {}
    for spec in peer:
        pname, p = _parse_peer(spec)
        if pname in peer_map:
            raise _die(f"--peer: duplicate name {pname!r}")
        peer_map[pname] = p
    missing = _REQUIRED_PEERS[role] - set(peer_map)
    if missing:
        raise _die(f"role {role!r} requires --peer for {sorted(missing)}")

    listen_pair = None
    if role in ("gateway", "issuer", "tool"):
        if not listen:
            raise _die(f"role {role!r} requires --listen HOST:PORT")
        listen_pair = _parse_listen(listen)
    elif listen:
        _warn(f"--listen ignored for role {role!r}")

    stores = stores_backend if role in ("gateway", "issuer") else None
    workload = workload_seed or Path("keys") / f"{name}.seed"
    governor = governor_seed or Path("keys") / "issuer.seed"

    if gen_seed:
        if role != "agent":
            raise _die("--gen-seed only applies to --role agent")
        pub = workload.with_suffix(".pub")
        if (pub.exists() or workload.exists()) and not force:
            raise _die(f"{pub} or {workload} exists (pass --force)")
        _generate_keypair(pub, workload)
        _ok(f"generated {pub}")
        _ok(f"generated {workload}  (private, agent only)")

    doc: dict = {
        "role": role,
        "spiffe_id": spiffe_id,
        "environment": environment,
        "tls": {
            "cert_file": cert,
            "key_file": key,
            "ca_file": ca,
            "trust_domains": [domain],
        },
        "governance": {
            "bundle_file": bundle,
            "state_file": state_file,
            "authority_keys": [authority_b64],
            "reload_interval_seconds": 30,
            "min_version": 1,
        },
    }
    if listen_pair:
        doc["listen"] = {"host": listen_pair[0], "port": listen_pair[1]}
    if stores:
        doc["stores"] = {"backend": stores}
    if peer_map:
        doc["peers"] = peer_map
    if role == "agent":
        doc["key"] = {"seed_file": workload}
    if role == "issuer":
        doc["issuer"] = {"root_seed_file": governor}

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_render_node_toml(doc), encoding="utf-8")
    _ok(f"wrote {out}")
    try:
        load_node_config(out)
        _ok("validated")
    except ConfigError as exc:
        _warn(f"not yet loadable: {exc}")
        _warn("  (normal during bootstrapping — generate certs and sign the bundle)")


# ═════════════════════════════════════════════════════════════════════════
# show / validate / sign
# ═════════════════════════════════════════════════════════════════════════

def _summarize(doc: dict) -> dict:
    return {
        "version": doc.get("version"),
        "not_before": _show_time(doc.get("not_before")),
        "expires_at": _show_time(doc.get("expires_at")),
        "trust": {
            "roots": [
                {"issuer": r["issuer"], "keys": [thumbprint(k) for k in r["keys"]]}
                for r in doc["trust"]["roots"]
            ],
            "enrollment": (
                thumbprint(doc["trust"]["enrollment"]) if "enrollment" in doc["trust"] else None
            ),
        },
        "policy": {
            "max_depth": doc["policy"]["max_depth"],
            "models": doc["policy"]["models"],
            "edges": len(doc["policy"]["edges"]),
        },
        "issuance": len(doc.get("issuance", [])),
        "enrollment": bool(doc.get("enrollment")),
        "pricing": {
            "rules": len(doc["pricing"]["rules"]),
            "default": doc["pricing"].get("default"),
        },
    }


def _collect_warnings(doc: dict) -> list[str]:
    out: list[str] = []
    now = dt.datetime.now(dt.timezone.utc)

    def _as_utc(v: Any) -> dt.datetime | None:
        if isinstance(v, dt.datetime):
            return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)
        if isinstance(v, str):
            try:
                s = v.replace("Z", "+00:00")
                return dt.datetime.fromisoformat(s)
            except ValueError:
                return None
        return None

    exp = _as_utc(doc.get("expires_at"))
    if exp is not None:
        delta = exp - now
        if delta.days < 0:
            out.append(f"expires_at is in the past ({_show_time(exp)})")
        elif delta.days < 30:
            out.append(f"expires_at is within {delta.days} day(s)")

    nb = _as_utc(doc.get("not_before"))
    if nb is not None and nb > now:
        out.append(f"not_before is in the future ({_show_time(nb)})")

    if not doc.get("issuance") and doc.get("policy", {}).get("edges"):
        out.append("edges exist but no [[issuance]] rules — no one can be issued tokens")

    if "enrollment" in doc.get("trust", {}) and not doc.get("enrollment"):
        out.append("enrollment key is pinned but no [enrollment] policy is set")

    return out


@app.command("show")
def show(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON instead of a table")] = False,
) -> None:
    """Summarize governance.toml. Read-only."""
    doc = _load_decoded(state.file)
    summary = _summarize(doc)
    if as_json:
        stdout.print(json.dumps(summary, indent=2, default=str))
        return

    roots = Table(title="Trust Roots", show_header=True, header_style="bold cyan")
    roots.add_column("issuer")
    roots.add_column("keys", justify="right")
    roots.add_column("thumbprints", style="dim")
    for r in doc["trust"]["roots"]:
        tps = ", ".join(thumbprint(k)[:16] + ".." for k in r["keys"])
        roots.add_row(r["issuer"], str(len(r["keys"])), tps)
    stdout.print(roots)

    if "enrollment" in doc["trust"]:
        k = doc["trust"]["enrollment"]
        stdout.print(
            f"[bold]enrollment[/bold]  {_encode(k, 'raw_b64')}  "
            f"[dim]sha256={thumbprint(k)[:16]}..[/dim]"
        )

    meta = Table(title="Metadata", show_header=False, title_justify="left")
    meta.add_column("field", style="cyan")
    meta.add_column("value")
    for key in ("version", "not_before", "expires_at"):
        meta.add_row(key, str(doc.get(key, "?")))
    meta.add_row("max_depth", str(doc["policy"]["max_depth"]))
    meta.add_row("models", ", ".join(doc["policy"]["models"]))
    meta.add_row("edges", str(len(doc["policy"]["edges"])))
    meta.add_row("issuance", f"{len(doc.get('issuance', []))} rule(s)")
    meta.add_row("enrollment", "set" if doc.get("enrollment") else "unset")
    meta.add_row(
        "pricing",
        f"{len(doc['pricing']['rules'])} rule(s), "
        f"default={'yes' if doc['pricing'].get('default') else 'no'}",
    )
    stdout.print(meta)


@app.command("validate")
def validate(
    as_json: Annotated[bool, typer.Option("--json")] = False,
    no_warnings: Annotated[bool, typer.Option("--no-warnings")] = False,
) -> None:
    """Run the exact validator nodes run at load time."""
    raw = _load(state.file)
    try:
        compile_document(raw)
    except ConfigError as exc:
        if as_json:
            stdout.print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            stderr.print(f"[bold red]invalid:[/bold red] {escape(str(exc))}")
        raise typer.Exit(2)

    warnings = [] if no_warnings else _collect_warnings(raw)
    for w in warnings:
        _warn(w)

    if as_json:
        stdout.print(json.dumps({"ok": True, "warnings": warnings}, indent=2))
    else:
        _ok("valid" + (f" ({len(warnings)} warning(s))" if warnings else ""))


@app.command("sign")
def sign(
    key: Annotated[Path, typer.Option("--key", help="Authority SEED (current)")],
    out: Annotated[Path, typer.Option("--out", help="Bundle output path")],
    next_key: Annotated[Path | None, typer.Option("--next-key", help="Authority SEED (rotation)")] = None,
) -> None:
    """Compile governance.toml and sign the bundle."""
    try:
        doc = compile_document(_load(state.file))
    except ConfigError as exc:
        raise _die(f"invalid: {exc}", 2)
    try:
        current = cc.CapChainKey.from_seed(load_seed(key))
        nxt = cc.CapChainKey.from_seed(load_seed(next_key)) if next_key else None
    except (OSError, ValueError) as exc:
        raise _die(f"key error: {exc}", 2)

    raw = sign_bundle_with_rotation(doc, current, nxt) if nxt is not None else sign_bundle(doc, current)

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    with tmp.open("wb") as fh:
        fh.write(raw)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(out)

    rotation = " [rotation]" if nxt is not None else ""
    _ok(f"signed → {out} ({len(raw)} bytes){rotation}")


# ═════════════════════════════════════════════════════════════════════════
# Trust roots
# ═════════════════════════════════════════════════════════════════════════

def _do_set_issuer(action: str, spiffe: str, key: Path | None, *, dry_run: bool) -> None:
    doc = _load_decoded(state.file)
    roots = doc["trust"]["roots"]

    if action == "add":
        if any(r["issuer"] == spiffe for r in roots):
            raise _die(f"issuer {spiffe} exists")
        if key is None:
            raise _die("--key required for add")
        roots.append({"issuer": spiffe, "keys": [load_raw(key)]})
    elif action == "add-key":
        target = next((r for r in roots if r["issuer"] == spiffe), None)
        if target is None:
            raise _die(f"issuer {spiffe} not found")
        if key is None:
            raise _die("--key required")
        raw = load_raw(key)
        if raw in target["keys"]:
            raise _die("key already present")
        target["keys"].append(raw)
    elif action == "remove-key":
        target = next((r for r in roots if r["issuer"] == spiffe), None)
        if target is None:
            raise _die(f"issuer {spiffe} not found")
        if key is None:
            raise _die("--key required")
        raw = load_raw(key)
        if raw not in target["keys"]:
            raise _die("key not present")
        target["keys"].remove(raw)
        if not target["keys"]:
            roots.remove(target)
    elif action == "remove":
        before = len(roots)
        roots[:] = [r for r in roots if r["issuer"] != spiffe]
        if len(roots) == before:
            raise _die(f"issuer {spiffe} not found")
        touched = [e for e in doc["policy"]["edges"] if spiffe in (e["parent"], e["child"])]
        if touched:
            _warn(f"{len(touched)} edge(s) reference {spiffe} and will become dead")
    else:
        raise _die(f"unknown action {action!r}")

    _commit(state.file, doc, dry_run=dry_run)
    _ok(f"{action} {spiffe}")


@app.command("set-issuer-add")
def set_issuer_add(
    spiffe: Annotated[str, typer.Argument()],
    key: Annotated[Path, typer.Option("--key")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Add a trust root (issuer + first key)."""
    _check_spiffe(spiffe)
    _do_set_issuer("add", spiffe, key, dry_run=dry_run)


@app.command("set-issuer-add-key")
def set_issuer_add_key(
    spiffe: Annotated[str, typer.Argument()],
    key: Annotated[Path, typer.Option("--key")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Add a key to an existing issuer."""
    _check_spiffe(spiffe)
    _do_set_issuer("add-key", spiffe, key, dry_run=dry_run)


@app.command("set-issuer-remove-key")
def set_issuer_remove_key(
    spiffe: Annotated[str, typer.Argument()],
    key: Annotated[Path, typer.Option("--key")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Remove a key from an issuer."""
    _check_spiffe(spiffe)
    _do_set_issuer("remove-key", spiffe, key, dry_run=dry_run)


@app.command("set-issuer-remove")
def set_issuer_remove(
    spiffe: Annotated[str, typer.Argument()],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Remove an issuer entirely."""
    _check_spiffe(spiffe)
    _do_set_issuer("remove", spiffe, None, dry_run=dry_run)


# ═════════════════════════════════════════════════════════════════════════
# Enrollment
# ═════════════════════════════════════════════════════════════════════════

@app.command("set-enrollment-key")
def set_enrollment_key(
    key: Annotated[Path, typer.Option("--key")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Pin the enrollment authority public key."""
    doc = _load_decoded(state.file)
    doc["trust"]["enrollment"] = load_raw(key)
    _commit(state.file, doc, dry_run=dry_run)
    _ok("enrollment key pinned")


@app.command("set-enrollment-policy")
def set_enrollment_policy(
    may_enroll: Annotated[str, typer.Option("--may-enroll")],
    ttl: Annotated[int, typer.Option("--ttl", min=1)],
    ceiling_tools: Annotated[str, typer.Option("--ceiling-tools")],
    ceiling_budget: Annotated[int, typer.Option("--ceiling-budget", min=0)],
    ceiling_audience: Annotated[str, typer.Option("--ceiling-audience")],
    ceiling_domains: Annotated[str, typer.Option("--ceiling-domains")] = "",
    model: Annotated[str, typer.Option("--model")] = "key_bound",
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Set the [enrollment] constraint block."""
    _check_spiffe(may_enroll)
    doc = _load_decoded(state.file)
    if "enrollment" not in doc["trust"]:
        raise _die("pin the key first: set-enrollment-key")
    doc["enrollment"] = {
        "may_enroll": may_enroll,
        "ttl": ttl,
        "model": model,
        "ceiling": _scope(ceiling_tools, ceiling_budget, ceiling_audience, ceiling_domains),
    }
    _commit(state.file, doc, dry_run=dry_run)
    _ok("enrollment policy set")


# ═════════════════════════════════════════════════════════════════════════
# Policy
# ═════════════════════════════════════════════════════════════════════════

@app.command("set-policy")
def set_policy(
    max_depth: Annotated[int | None, typer.Option("--max-depth", min=0)] = None,
    models: Annotated[str | None, typer.Option("--models")] = None,
    peer_bound_tools: Annotated[str | None, typer.Option("--peer-bound-tools")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Update [policy] scalars."""
    doc = _load_decoded(state.file)
    p = doc["policy"]
    if max_depth is not None:
        p["max_depth"] = max_depth
    if models is not None:
        p["models"] = _split(models)
    if peer_bound_tools is not None:
        p["peer_bound_tools"] = _split(peer_bound_tools)
    _commit(state.file, doc, dry_run=dry_run)
    _ok("policy updated")


# ═════════════════════════════════════════════════════════════════════════
# Edges
# ═════════════════════════════════════════════════════════════════════════

@app.command("add-edge")
def add_edge(
    parent: Annotated[str, typer.Option("--parent")],
    child: Annotated[str, typer.Option("--child")],
    max_ttl: Annotated[int, typer.Option("--max-ttl", min=1)],
    ceiling_tools: Annotated[str, typer.Option("--ceiling-tools")],
    ceiling_budget: Annotated[int, typer.Option("--ceiling-budget", min=0)],
    ceiling_audience: Annotated[str, typer.Option("--ceiling-audience")],
    max_children: Annotated[int, typer.Option("--max-children", min=1)] = 32,
    ceiling_domains: Annotated[str, typer.Option("--ceiling-domains")] = "",
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Append a delegation edge (parent → child, ceiling, max_ttl)."""
    _check_spiffe(parent)
    _check_spiffe(child)
    if parent == child:
        raise _die("edge parent and child must differ")
    doc = _load_decoded(state.file)
    if any(e["parent"] == parent and e["child"] == child for e in doc["policy"]["edges"]):
        raise _die("edge already exists")
    doc["policy"]["edges"].append(
        {
            "parent": parent,
            "child": child,
            "max_ttl": max_ttl,
            "max_children": max_children,
            "ceiling": _scope(ceiling_tools, ceiling_budget, ceiling_audience, ceiling_domains),
        }
    )
    _commit(state.file, doc, dry_run=dry_run)
    _ok(f"added edge {parent} → {child}")


@app.command("remove-edge")
def remove_edge(
    parent: Annotated[str, typer.Option("--parent")],
    child: Annotated[str, typer.Option("--child")],
    force: Annotated[bool, typer.Option("--force", help="Remove even if orphaned issuance exists")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Remove an edge identified by (parent, child)."""
    doc = _load_decoded(state.file)
    before = len(doc["policy"]["edges"])
    doc["policy"]["edges"] = [
        e for e in doc["policy"]["edges"] if not (e["parent"] == parent and e["child"] == child)
    ]
    if len(doc["policy"]["edges"]) == before:
        raise _die("edge not found")

    orphans = [r for r in doc.get("issuance", []) if r["holder"] == child]
    if orphans and not force:
        raise _die(
            f"{len(orphans)} issuance rule(s) target {child}; "
            "remove them first or pass --force"
        )
    if orphans:
        _warn(f"removing edge will orphan {len(orphans)} issuance rule(s)")

    _commit(state.file, doc, dry_run=dry_run, validate=not orphans)
    _ok(f"removed edge {parent} → {child}")


# ═════════════════════════════════════════════════════════════════════════
# Issuance
# ═════════════════════════════════════════════════════════════════════════

@app.command("add-issuance")
def add_issuance(
    holder: Annotated[str, typer.Option("--holder")],
    ttl: Annotated[int, typer.Option("--ttl", min=1)],
    scope_tools: Annotated[str, typer.Option("--scope-tools")],
    scope_budget: Annotated[int, typer.Option("--scope-budget", min=0)],
    scope_audience: Annotated[str, typer.Option("--scope-audience")],
    scope_domains: Annotated[str, typer.Option("--scope-domains")] = "",
    max_depth: Annotated[int, typer.Option("--max-depth", min=0)] = 1,
    model: Annotated[str, typer.Option("--model")] = "key_bound",
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Append an issuance rule. Refuses if the resulting config doesn't compile."""
    _check_spiffe(holder)
    doc = _load_decoded(state.file)
    if any(r["holder"] == holder for r in doc.get("issuance", [])):
        raise _die(f"issuance for {holder} exists")
    doc.setdefault("issuance", []).append(
        {
            "holder": holder,
            "ttl": ttl,
            "max_depth": max_depth,
            "model": model,
            "scope": _scope(scope_tools, scope_budget, scope_audience, scope_domains),
        }
    )
    _commit(state.file, doc, dry_run=dry_run)
    _ok(f"added issuance for {holder}")


@app.command("remove-issuance")
def remove_issuance(
    holder: Annotated[str, typer.Option("--holder")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Remove every issuance rule whose holder matches exactly."""
    doc = _load_decoded(state.file)
    before = len(doc.get("issuance", []))
    doc["issuance"] = [r for r in doc.get("issuance", []) if r["holder"] != holder]
    if len(doc["issuance"]) == before:
        raise _die(f"issuance for {holder} not found")
    _commit(state.file, doc, dry_run=dry_run)
    _ok(f"removed issuance for {holder}")


# ═════════════════════════════════════════════════════════════════════════
# Pricing
# ═════════════════════════════════════════════════════════════════════════

@app.command("add-pricing")
def add_pricing(
    tool: Annotated[str, typer.Option("--tool")],
    base: Annotated[int, typer.Option("--base", min=0)],
    per_kib: Annotated[int, typer.Option("--per-kib", min=0)] = 0,
    max_: Annotated[int | None, typer.Option("--max", min=0)] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Append an exact or namespace:* pricing rule."""
    doc = _load_decoded(state.file)
    if any(r["tool"] == tool for r in doc["pricing"]["rules"]):
        raise _die(f"pricing for {tool} exists")
    doc["pricing"]["rules"].append(
        {"tool": tool, "base_micros": base, "per_kib_micros": per_kib, "max_micros": max_}
    )
    _commit(state.file, doc, dry_run=dry_run)
    _ok(f"added pricing for {tool}")


@app.command("remove-pricing")
def remove_pricing(
    tool: Annotated[str, typer.Option("--tool")],
    force: Annotated[bool, typer.Option("--force", help="Write even if the result is invalid")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Remove a pricing rule by exact tool name."""
    doc = _load_decoded(state.file)
    before = len(doc["pricing"]["rules"])
    doc["pricing"]["rules"] = [r for r in doc["pricing"]["rules"] if r["tool"] != tool]
    if len(doc["pricing"]["rules"]) == before:
        raise _die(f"pricing for {tool} not found")
    _commit(state.file, doc, dry_run=dry_run, validate=not force)
    _ok(f"removed pricing for {tool}")


@app.command("set-default-pricing")
def set_default_pricing(
    base: Annotated[int, typer.Option("--base", min=0)],
    per_kib: Annotated[int, typer.Option("--per-kib", min=0)] = 0,
    max_: Annotated[int | None, typer.Option("--max", min=0)] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Set the fallback price."""
    doc = _load_decoded(state.file)
    doc["pricing"]["default"] = {
        "base_micros": base,
        "per_kib_micros": per_kib,
        "max_micros": max_,
    }
    _commit(state.file, doc, dry_run=dry_run)
    _ok("default pricing set")


# ═════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════

def main() -> None:
    try:
        app()
    except ConfigError as exc:
        stderr.print(f"[bold red]error:[/bold red] {escape(str(exc))}")
        sys.exit(2)
    except (OSError, ValueError) as exc:
        stderr.print(f"[bold red]error:[/bold red] {escape(str(exc))}")
        sys.exit(1)
    except KeyboardInterrupt:
        stderr.print("[yellow]interrupted[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()