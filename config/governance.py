


""" 
The signed governance bundle
delegation edges and policy:
Edges are ordered; first match wins. Ceilings are checked at compile time
(``governance.py::
``) and again at issue time (pattern rules).

``match_spiffe`` implements the only wildcard shape supported in a SPIFFE
identity: a single trailing ``/*`` matching exactly one path segment.

Pricing model for tool calls:
Prices are deterministic: base + per_kib * ceil(bytes/1024), capped at max.
A tool must be covered either by an exact rule, a ``namespace:*`` wildcard,
or the ``default`` rule. The compiler rejects scopes whose tools are not
covered (see ``governance.py::_cross_check``).


The signed governance bundle:
One artifact carries trust roots, delegation policy, issuance rules, and
pricing. Every node loads the same bytes, so Issuer, every parent agent,
and Gateway cannot disagree about policy.

Compile-time guarantees
  * ``compile_document`` runs the same validator nodes will run, so a
    document the compiler accepts cannot fail at load time.
  * ``_cross_check`` rejects scopes whose tools are not priced; ``"*"``
    scopes require a default pricing rule.
  * Edge cycles are rejected.

Bundle envelope
  Separate from capchain's ``Signed`` on purpose: ``Signed`` is capped at
  8 KiB (PoP-sized). Bundles have their own domain-separation context, so
  a bundle signature can never be confused with a PoP or a block.

Rotation
  ``sign_bundle_with_rotation`` produces an envelope with TWO signatures:
  current and next. A node that accepts a co-signed bundle learns the
  next authority key from the bundle itself. See ``runtime.py`` for how
  the loader persists and applies this.


load, rollback-protect, and hot-reload the bundle.

Rollback protection: a validly signed OLD bundle can re-enable a revoked root
or a widened edge. The loader persists (version, digest) of the newest accepted
bundle and refuses anything older, or a different bundle claiming the same
version. Keep state_file on a persistent volume the node's workload cannot reset.

Rotation (overlap window): during a rotation, a node accepts signatures from
both ``authority_keys`` (current) and ``previous_authority_keys`` (old), until
``previous_keys_expire_at``. Warns when the accepted bundle is signed by a
previous key so the operator knows to finish the rotation.

Rotation (signed-forward): if a bundle envelope carries ``key_next``, the loader
persists it as the next authority. A subsequent bundle signed by that key is
accepted as the new authority. This makes the current authority approve its
own successor cryptographically. Requires accepting an updated envelope that
carries both ``authority_keys`` (from node config) and ``next_authorities``
(from state).

Reload: each version builds its own component (Gateway, issuer handler).
A request takes ONE (Governance, component) pair via current() and uses it for
the whole decision, so a reload never mixes two policy versions inside one
admission.


Local and unsigned, so it holds no policy and no secrets:
  * secrets live in files (seed_file) or environment variables (*_env names);
    an inline 'postgres_dsn = ...' is rejected as an unknown key
  * policy lives in the signed governance bundle
Relative paths resolve against the config file's directory
"""


from __future__ import annotations
import base64
import os
import asyncio
import hmac
import json
import logging
import time
from pathlib import Path
from typing import Callable, Generic, TypeVar


from dataclasses import dataclass, field
from typing import Iterable
import math
import libs.capchain.capchain as cc
import hashlib
import hmac
import json
from typing import Any, Iterable, Mapping
import re
import tomllib 
from config._schema import (
    ConfigError, epoch, integer, spiffe, table, tables, text, texts, file_path, number
)




KEY_BYTES = 32
SEED_BYTES = 32
_PATH_HINTS = (".pub", ".seed", ".key", ".bin")



ROLES = frozenset({"gateway", "issuer", "agent", "tool"})
ENVIRONMENTS = frozenset({"production", "development"})
_REQUIREMENTS = {
    "gateway": ({"listen", "stores"}, {"tool"}),
    "issuer":  ({"listen", "stores", "issuer"}, set()),
    "agent":   (set(), {"gateway", "parent"}),
    "tool":    ({"listen"}, {"gateway"}),
}
_PEER_NAME = re.compile(r"[a-z][a-z0-9._-]{0,31}")


MAX_EDGES = 256   # capchain's canonical codec caps lists at 256
BUNDLE_FORMAT = 1
CTX_GOVERNANCE = b"aegis/governance-bundle/v1"
MAX_BUNDLE_BYTES = 1 << 20
MAX_BUNDLE_LIFETIME = 90 * 86400
CLOCK_SKEW = 60

_KNOWN_MODELS = frozenset({cc.Model.PEER_BOUND, cc.Model.KEY_BOUND})
T = TypeVar("T")
EXPIRY_WARNING_SECONDS = 86400
EXPIRY_LOG_INTERVAL_SECONDS = 3600

log = logging.getLogger(__name__)




def match_spiffe(pattern: str, concrete: str) -> bool:
    """True if ``concrete`` matches ``pattern``.

    Patterns may end with ``/*`` to match exactly one path segment.
    A pattern with no wildcard matches exactly.
    """
    if pattern == concrete:
        return True
    if pattern.endswith("/*"):
        base = pattern[:-2]
        if not concrete.startswith(base + "/"):
            return False
        rest = concrete[len(base) + 1:]
        return "/" not in rest and rest != ""
    return False


@dataclass(frozen=True, slots=True)
class EdgeRule:
    parent: str             # pattern (may end with /*)
    child: str              # pattern (may end with /*)
    ceiling: cc.Scope       # max scope the child may receive under this edge
    max_ttl: int
    max_children: int

    def __post_init__(self) -> None:
        if self.max_ttl <= 0 or self.max_children <= 0:
            raise ValueError("max_ttl and max_children must be positive")
        if not isinstance(self.ceiling, cc.Scope):
            raise ValueError("ceiling must be a Scope")


@dataclass(frozen=True, slots=True)
class Policy:
    version: int
    root_issuers: frozenset[str]
    edges: tuple[EdgeRule, ...]
    max_depth: int
    allowed_models: frozenset[str]
    peer_bound_tools: frozenset[str]

    def __post_init__(self) -> None:
        if not self.root_issuers:
            raise ValueError("at least one root issuer required")
        if len(self.edges) > MAX_EDGES:
            raise ValueError(f"edges exceed MAX_EDGES ({MAX_EDGES})")
        if self.max_depth < 0:
            raise ValueError("max_depth must be non-negative")

    def edge(self, parent: str, child: str) -> EdgeRule | None:
        """First matching edge, or None.

        Both sides use ``match_spiffe`` so a concrete parent can match a
        pattern edge and vice versa.
        """
        for e in self.edges:
            if match_spiffe(e.parent, parent) and match_spiffe(e.child, child):
                return e
        return None

    def allows_root(self, issuer: str) -> bool:
        return issuer in self.root_issuers




@dataclass(frozen=True, slots=True)
class ToolCost:
    base_micros: int
    per_kib_micros: int = 0
    max_micros: int | None = None

    def __post_init__(self) -> None:
        if self.base_micros < 0 or self.per_kib_micros < 0:
            raise ValueError("micros must be non-negative")
        if self.max_micros is not None and self.max_micros < self.base_micros:
            raise ValueError("max_micros must be >= base_micros")

    def price(self, size_bytes: int) -> int:
        kib = math.ceil(max(0, size_bytes) / 1024)
        total = self.base_micros + self.per_kib_micros * kib
        if self.max_micros is not None:
            total = min(total, self.max_micros)
        return total



@dataclass(frozen=True, slots=True)
class CostRule:
    tool: str               # exact or ``namespace:*``
    cost: ToolCost

    def __post_init__(self) -> None:
        if not self.tool:
            raise ValueError("tool must be non-empty")
        if not isinstance(self.cost, ToolCost):
            raise ValueError("cost must be a ToolCost")

    def matches(self, tool: str) -> bool:
        if self.tool == tool:
            return True
        if self.tool.endswith(":*"):
            return tool.startswith(self.tool[:-1])   # keep the colon
        return False


class StaticCostModel:
    def __init__(self, rules: Iterable[CostRule], *,
                 default: ToolCost | None = None) -> None:
        self._rules = tuple(rules)
        self._default = default
        self._exact: dict[str, ToolCost] = {}
        self._wild: dict[str, ToolCost] = {}
        for r in self._rules:
            if r.tool.endswith(":*"):
                self._wild[r.tool[:-2]] = r.cost
            else:
                self._exact[r.tool] = r.cost

    def price(self, tool: str, size_bytes: int) -> int:
        cost = self._lookup(tool)
        if cost is None:
            raise ValueError(f"no pricing rule for {tool!r}")
        return cost.price(size_bytes)

    def _lookup(self, tool: str) -> ToolCost | None:
        if tool in self._exact:
            return self._exact[tool]
        ns, _, _ = tool.partition(":")
        if ns in self._wild:
            return self._wild[ns]
        return self._default

    def covers(self, tool: str) -> bool:
        return self._lookup(tool) is not None

    def covers_any(self) -> bool:
        """True if a default pricing rule exists, so any tool is priced."""
        return self._default is not None

    def covers_namespace(self, tool: str) -> bool:
        """True if any rule covers ``tool`` OR its namespace."""
        if self.covers(tool):
            return True
        ns, _, _ = tool.partition(":")
        return ns in self._wild
    


@dataclass(frozen=True, slots=True)
class IssuanceRule:
    holder: str
    scope: cc.Scope
    ttl: int
    max_depth: int
    model: str

    def matches(self, holder: str) -> bool:
        return match_spiffe(self.holder, holder)


@dataclass(frozen=True, slots=True)
class IssuanceRules:
    rules: tuple[IssuanceRule, ...]

    def find(self, holder: str) -> IssuanceRule | None:
        return next((r for r in self.rules if r.matches(holder)), None)


@dataclass(frozen=True, slots=True)
class EnrollmentRule:
    may_enroll: str
    ceiling: cc.Scope
    ttl: int
    model: str

    def allows(self, holder: str) -> bool:
        return match_spiffe(self.may_enroll, holder)


@dataclass(frozen=True, slots=True)
class Governance:
    version: int
    not_before: int
    expires_at: int
    digest: str
    roots: cc.TrustedRoots
    policy: Policy
    cost: StaticCostModel
    issuance: IssuanceRules
    enrollment: EnrollmentRule | None = None

    def check_live(self, now: int) -> None:
        if now + CLOCK_SKEW < self.not_before:
            raise cc.error(cc.Code.STATE_UNAVAILABLE,
                            f"governance v{self.version} not yet valid")
        if now >= self.expires_at:
            raise cc.error(cc.Code.STATE_UNAVAILABLE,
                            f"governance v{self.version} expired")


def _model(value: Any, where: str) -> str:
    m = text(value, where, 32)
    if m not in _KNOWN_MODELS:
        raise ConfigError(
            f"{where}: {m!r} is not a capchain model "
            f"(expected one of {sorted(_KNOWN_MODELS)})")
    return m

def _scope(value: Any, where: str) -> cc.Scope:
    t = table(value, where, ("tools", "budget", "audience"), ("domains",))
    try:
        return cc.Scope(
            tools=frozenset(texts(t["tools"], f"{where}.tools")),
            budget_micros=integer(t["budget"], f"{where}.budget"),
            audience=frozenset(texts(t["audience"], f"{where}.audience")),
            domains=frozenset(texts(t.get("domains", []), f"{where}.domains")),
        )
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None


def _compile_cost(value: Any, where: str, *, with_tool: bool) -> dict:
    required = ("tool", "base_micros") if with_tool else ("base_micros",)
    t = table(value, where, required, ("per_kib_micros", "max_micros"))
    out = {
        "base": t["base_micros"],
        "per_kib": t.get("per_kib_micros", 0),
        "max": t.get("max_micros"),
    }
    if with_tool:
        out["tool"] = t["tool"]
    return out


def _parse_cost(value: Any, where: str, *,
                with_tool: bool) -> tuple[str | None, ToolCost]:
    keys = ("base", "per_kib", "max") + (("tool",) if with_tool else ())
    t = table(value, where, keys)
    try:
        cost = ToolCost(
            base_micros=integer(t["base"], f"{where}.base"),
            per_kib_micros=integer(t["per_kib"], f"{where}.per_kib"),
            max_micros=None if t["max"] is None else integer(t["max"], f"{where}.max"),
        )
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None
    return (text(t["tool"], f"{where}.tool", 257) if with_tool else None), cost


def _bad_list(where: str):
    raise ConfigError(f"{where}: expected a list")


def _has_cycle(edges: list[EdgeRule]) -> bool:
    """DFS for a cycle in the parent→child graph. Returns True if any."""
    WHITE, GRAY, BLACK = 0, 1, 2
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e.parent, []).append(e.child)
    color: dict[str, int] = {}

    def visit(n: str) -> bool:
        color[n] = GRAY
        for c in adj.get(n, ()):
            if color.get(c, WHITE) == GRAY:
                return True
            if color.get(c, WHITE) == WHITE and visit(c):
                return True
        color[n] = BLACK
        return False

    return any(
        color.get(n, WHITE) == WHITE and visit(n)
        for n in list(adj)
    )



def _encode(doc: Mapping[str, Any]) -> bytes:
    try:
        return cc.encode(dict(doc))
    except cc.RejectError as exc:
        raise ConfigError(f"document not encodable: {exc.detail or exc.code}") from None


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ConfigError(f"duplicate key {key!r} in bundle envelope")
        out[key] = value
    return out


def _encode_envelope(envelope: Mapping[str, Any]) -> bytes:
    return json.dumps(
        envelope, sort_keys=True, separators=(",", ":")
    ).encode("ascii")









class _State:
    """Persisted between restarts: (version, digest, authority_keys, next_keys)."""
    __slots__ = ("version", "digest", "authority_keys", "next_keys")

    def __init__(self, version: int, digest: str,
                 authority_keys: tuple[bytes, ...],
                 next_keys: tuple[bytes, ...]) -> None:
        self.version = version
        self.digest = digest
        self.authority_keys = authority_keys
        self.next_keys = next_keys


class GovernanceLoader:
    def __init__(
        self,
        *,
        bundle_file: Path,
        state_file: Path,
        authority_keys: tuple[bytes, ...],
        min_version: int = 1,
        previous_authority_keys: tuple[bytes, ...] = (),
        previous_keys_expire_at: int | None = None,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        if previous_authority_keys and previous_keys_expire_at is None:
            raise ConfigError(
                "previous_authority_keys requires previous_keys_expire_at")
        if previous_keys_expire_at is not None and not previous_authority_keys:
            raise ConfigError(
                "previous_keys_expire_at has no previous_authority_keys to bound")
        self._bundle_file = Path(bundle_file)
        self._state_file = Path(state_file)
        self._authority_keys = tuple(authority_keys)
        self._previous_keys = tuple(previous_authority_keys)
        self._previous_expires_at = previous_keys_expire_at
        self._min_version = min_version
        self._clock = clock

    def load(self) -> Governance:
        try:
            raw = self._bundle_file.read_bytes()
        except OSError as exc:
            raise ConfigError(
                f"cannot read bundle {self._bundle_file}: {exc}") from None

        now = self._clock()
        prior = self._read_state()

        accepted: list[bytes] = list(self._authority_keys)
        overlap_active = (
            self._previous_keys
            and self._previous_expires_at is not None
            and now < self._previous_expires_at
        )
        if overlap_active:
            accepted.extend(self._previous_keys)
        if prior is not None:
            accepted.extend(prior.next_keys)

        gov, signer_pk, next_pk = open_bundle_with_signer(raw, accepted)
        gov.check_live(now)

        if signer_pk not in self._authority_keys:
            if signer_pk in self._previous_keys:
                remaining = (self._previous_expires_at - now) // 86400 # type: ignore
                log.warning(
                    "governance v%d signed by a previous authority key; "
                    "re-sign with a current key before the overlap expires "
                    "(%d day(s) left)",
                    gov.version, remaining)
            elif prior is not None and signer_pk in prior.next_keys:
                log.info(
                    "governance v%d accepted under a signed-forward rotation",
                    gov.version)
            else:
                raise ConfigError("bundle signer is not a trusted authority")

        if gov.version < self._min_version:
            raise ConfigError(
                f"bundle v{gov.version} is below min_version v{self._min_version}; "
                f"the wrong bundle may be mounted")

        self._enforce_monotonic(gov, next_pk)
        return gov

    def _enforce_monotonic(self, gov: Governance,
                           next_pk: bytes | None) -> None:
        prior = self._read_state()
        if prior is not None:
            if gov.version < prior.version:
                raise ConfigError(
                    f"rollback refused: bundle v{gov.version} < accepted "
                    f"v{prior.version}")
            if gov.version == prior.version:
                if not hmac.compare_digest(gov.digest, prior.digest):
                    raise ConfigError(
                        f"equivocation: a different bundle also claims "
                        f"v{gov.version}")
                return
        self._write_state(
            gov.version, gov.digest,
            tuple(self._authority_keys),
            (next_pk,) if next_pk is not None else (),
        )

    def _read_state(self) -> _State | None:
        try:
            raw = self._state_file.read_text("utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConfigError(
                f"governance state unreadable ({self._state_file}): {exc}") from None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ConfigError(
                f"governance state corrupt: {self._state_file}: {exc}") from None
        if (not isinstance(data, dict)
                or type(data.get("version")) is not int
                or not isinstance(data.get("digest"), str)):
            raise ConfigError(f"governance state corrupt: {self._state_file}")
        try:
            auth = tuple(cc.b64d(k)
                         for k in data.get("authority_keys", ()))
            nxt = tuple(cc.b64d(k)
                        for k in data.get("next_keys", ()))
        except cc.RejectError:
            raise ConfigError(f"governance state corrupt: {self._state_file}")
        return _State(data["version"], data["digest"], auth, nxt)

    def _write_state(
        self, version: int, digest: str,
        authority_keys: tuple[bytes, ...],
        next_keys: tuple[bytes, ...],
    ) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_file.with_name(self._state_file.name + ".tmp")
        payload = {
            "version": version,
            "digest": digest,
            "authority_keys": [cc.b64e(k) for k in authority_keys],
            "next_keys": [cc.b64e(k) for k in next_keys],
        }
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._state_file)
        _fsync_dir(self._state_file.parent)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class GovernanceRuntime(Generic[T]):
    def __init__(self, loader: GovernanceLoader,
                 build: Callable[[Governance], T], *,
                 reload_interval: float,
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        self._loader = loader
        self._build = build
        self._interval = reload_interval
        self._clock = clock
        self._current: tuple[Governance, T] | None = None
        self._task: asyncio.Task | None = None
        self._last_expiry_warning = 0

    def load_initial(self) -> Governance:
        """Load and build the first version.

        A ConfigError here means: do not start.
        """
        gov = self._loader.load()
        self._current = (gov, self._build(gov))
        log.info("governance v%d loaded digest=%s",
                 gov.version, gov.digest[:16])
        return gov

    def current(self) -> tuple[Governance, T]:
        """Take one snapshot per request.

        Raises Reject(STATE_UNAVAILABLE) if expired or not loaded.
        """
        cur = self._current
        if cur is None:
            raise cc.error(cc.Code.STATE_UNAVAILABLE, "governance not loaded")
        cur[0].check_live(self._clock())
        return cur

    def reload(self) -> bool:
        """Returns True if a newer version was installed. Never raises."""
        try:
            gov = self._loader.load()
        except ConfigError as exc:
            held = self._current[0].version if self._current else None
            log.error("governance reload rejected (keeping v%s): %s",
                      held, exc)
            return False
        cur = self._current
        if cur is not None and gov.version == cur[0].version:
            return False
        try:
            built = self._build(gov)
        except Exception:
            log.exception("governance v%d failed to build; keeping previous",
                          gov.version)
            return False
        self._current = (gov, built)      # single reference swap
        log.info("governance v%d installed digest=%s",
                 gov.version, gov.digest[:16])
        return True

    def start(self) -> None:
        """Load the initial bundle (if not already loaded) and start watching.

        Guarantees ``current()`` will not raise STATE_UNAVAILABLE for lack
        of a bundle after this returns.
        """
        if self._current is None:
            self.load_initial()   # raises -> node refuses to start
        self._task = asyncio.get_running_loop().create_task(self._watch())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _watch(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            await asyncio.to_thread(self.reload)
            cur = self._current
            if cur is None:
                continue
            remaining = cur[0].expires_at - self._clock()
            if 0 < remaining < EXPIRY_WARNING_SECONDS:
                now = self._clock()
                if now - self._last_expiry_warning >= EXPIRY_LOG_INTERVAL_SECONDS:
                    log.warning(
                        "governance v%d expires in %.1fh; ship a new bundle",
                        cur[0].version, remaining / 3600)
                    self._last_expiry_warning = now







@dataclass(frozen=True, slots=True)
class TlsConfig:
    cert_file: Path
    key_file: Path
    ca_file: Path
    trust_domains: frozenset[str]


@dataclass(frozen=True, slots=True)
class GovernanceConfig:
    bundle_file: Path
    state_file: Path
    authority_keys: tuple[bytes, ...]
    reload_interval: float
    min_version: int = 1
    previous_authority_keys: tuple[bytes, ...] = ()
    previous_keys_expire_at: int | None = None


@dataclass(frozen=True, slots=True)
class Listen:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int
    spiffe_id: str


@dataclass(frozen=True, slots=True)
class StoresConfig:
    backend: str
    redis_url: str | None = field(default=None, repr=False)
    postgres_dsn: str | None = field(default=None, repr=False)
    schema: str | None = None
    prefix: str | None = None

    def open_kwargs(self) -> dict[str, str]:
        pairs = {
            "redis_url": self.redis_url,
            "postgres_dsn": self.postgres_dsn,
            "schema": self.schema,
            "prefix": self.prefix,
        }
        return {k: v for k, v in pairs.items() if v is not None}


@dataclass(frozen=True, slots=True)
class NodeConfig:
    path: Path
    role: str
    spiffe_id: str
    environment: str
    tls: TlsConfig
    governance: GovernanceConfig
    listen: Listen | None
    peers: Mapping[str, Endpoint]
    stores: StoresConfig | None
    key_seed_file: Path | None
    root_seed_file: Path | None

    def peer(self, name: str) -> Endpoint:
        try:
            return self.peers[name]
        except KeyError:
            raise ConfigError(
                f"{self.path}: peers.{name} is not configured") from None


def _pubkey(value: Any, where: str) -> bytes:
    try:
        raw = cc.b64d(text(value, where, 64))
    except cc.RejectError:
        raise ConfigError(f"{where}: invalid base64") from None
    if len(raw) != cc.PUBLIC_KEY_BYTES:
        raise ConfigError(
            f"{where}: expected a {cc.PUBLIC_KEY_BYTES}-byte Ed25519 public key")
    return raw


def _env(t: Mapping[str, Any], key: str, where: str) -> str | None:
    if key not in t:
        return None
    name = text(t[key], f"{where}.{key}", 128)
    value = os.environ.get(name)
    if not value:
        raise ConfigError(
            f"{where}.{key}: environment variable {name} is not set")
    return value


def _host_port(t: Mapping[str, Any], where: str) -> tuple[str, int]:
    return (text(t["host"], f"{where}.host", 253),
            integer(t["port"], f"{where}.port", 1, 65535))

def load_seed(source: str | bytes | Path) -> bytes:
    """Read an Ed25519 seed.

    Accepts:
      - raw 32-byte files
      - base64 (standard or URL-safe, with or without ``base64:`` prefix)
      - hex (64 chars)

    Refuses group/world-readable files on POSIX.
    """
    if isinstance(source, bytes):
        if len(source) != cc.PRIVATE_SEED_BYTES:
            raise ConfigError(
                f"seed: expected {cc.PRIVATE_SEED_BYTES} bytes, "
                f"got {len(source)}")
        return source

    path = Path(source)
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ConfigError(
            f"{path}: secret file must not be group/world accessible "
            f"(chmod 600)")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(
            f"{path}: unreadable ({type(exc).__name__})") from None

    # Raw 32-byte seed file
    if len(raw) == cc.PRIVATE_SEED_BYTES:
        return raw

    # Otherwise: parse as text
    try:
        s = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise ConfigError(
            f"{path}: not a raw {cc.PRIVATE_SEED_BYTES}-byte seed "
            f"and not ASCII text ({len(raw)} bytes)") from None

    while s.startswith("base64:"):
        s = s[len("base64:"):]

    # hex?
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            seed = bytes.fromhex(s)
        except ValueError:
            seed = b""
        if len(seed) == cc.PRIVATE_SEED_BYTES:
            return seed

    # base64 (url-safe or standard)?
    core = s.rstrip("=")
    padded = core + "=" * (-len(core) % 4)
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            seed = decode(padded)
        except Exception:
            continue
        if len(seed) == cc.PRIVATE_SEED_BYTES:
            return seed

    raise ConfigError(
        f"{path}: cannot decode as raw {cc.PRIVATE_SEED_BYTES}B, "
        f"b64, or hex")

def load_node_config(path: str | Path) -> NodeConfig:
    path = Path(path).resolve()
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError:
        raise ConfigError(f"{path}: not found") from None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
    base = path.parent

    t = table(raw, "node", ("role", "spiffe_id", "tls", "governance"),
              ("environment", "listen", "peers", "stores", "key", "issuer"))
    role = text(t["role"], "role")
    if role not in ROLES:
        raise ConfigError(f"role: expected one of {sorted(ROLES)}")
    environment = t.get("environment", "production")
    if environment not in ENVIRONMENTS:
        raise ConfigError(
            f"environment: expected one of {sorted(ENVIRONMENTS)}")

    tt = table(t["tls"], "tls",
               ("cert_file", "key_file", "ca_file", "trust_domains"))
    domains = frozenset(texts(tt["trust_domains"], "tls.trust_domains", 16))
    if not domains or any("/" in d or ":" in d for d in domains):
        raise ConfigError(
            "tls.trust_domains: expected bare trust-domain names, e.g. ['aegis']")
    tls = TlsConfig(
        cert_file=file_path(tt["cert_file"], "tls.cert_file", base),
        key_file=file_path(tt["key_file"], "tls.key_file", base),
        ca_file=file_path(tt["ca_file"], "tls.ca_file", base),
        trust_domains=domains,
    )

    gt = table(t["governance"], "governance",
               ("bundle_file", "state_file", "authority_keys"),
               ("reload_interval_seconds", "min_version",
                "previous_authority_keys", "previous_keys_expire_at"))
    keys = tuple(
        _pubkey(k, f"governance.authority_keys[{i}]")
        for i, k in enumerate(texts(
            gt["authority_keys"], "governance.authority_keys", 8))
    )
    if not keys:
        raise ConfigError("governance.authority_keys: at least one key required")

    prev_keys_raw = gt.get("previous_authority_keys")
    prev_keys = (tuple(
        _pubkey(k, f"governance.previous_authority_keys[{i}]")
        for i, k in enumerate(texts(
            prev_keys_raw, "governance.previous_authority_keys", 8))
    ) if prev_keys_raw is not None else ())

    prev_exp_raw = gt.get("previous_keys_expire_at")
    prev_exp = (epoch(prev_exp_raw, "governance.previous_keys_expire_at")
                if prev_exp_raw is not None else None)

    if prev_keys and prev_exp is None:
        raise ConfigError(
            "governance.previous_authority_keys requires "
            "governance.previous_keys_expire_at (a bounded overlap window)")
    if prev_exp is not None and not prev_keys:
        raise ConfigError(
            "governance.previous_keys_expire_at has no "
            "governance.previous_authority_keys to bound")

    governance = GovernanceConfig(
        bundle_file=file_path(gt["bundle_file"],
                              "governance.bundle_file", base),
        state_file=file_path(gt["state_file"],
                             "governance.state_file", base, must_exist=False),
        authority_keys=keys,
        reload_interval=number(
            gt.get("reload_interval_seconds", 30),
            "governance.reload_interval_seconds", 1, 3600),
        min_version=integer(
            gt.get("min_version", 1),
            "governance.min_version", lo=1),
        previous_authority_keys=prev_keys,
        previous_keys_expire_at=prev_exp,
    )

    listen = None
    if "listen" in t:
        listen = Listen(*_host_port(
            table(t["listen"], "listen", ("host", "port")), "listen"))

    peers: dict[str, Endpoint] = {}
    raw_peers = t.get("peers", {})
    if not isinstance(raw_peers, Mapping):
        raise ConfigError("peers: expected a table of named peers")
    for name, value in raw_peers.items():
        if not _PEER_NAME.fullmatch(name):
            raise ConfigError(f"peers.{name}: invalid peer name")
        pt = table(value, f"peers.{name}", ("host", "port", "spiffe_id"))
        host, port = _host_port(pt, f"peers.{name}")
        peers[name] = Endpoint(
            host, port, spiffe(pt["spiffe_id"], f"peers.{name}.spiffe_id"))

    stores = None
    if "stores" in t:
        st = table(t["stores"], "stores", ("backend",),
                   ("redis_url_env", "postgres_dsn_env", "schema", "prefix"))
        backend = text(st["backend"], "stores.backend")
        if backend not in {"memory", "redis", "database"}:
            raise ConfigError(
                "stores.backend: expected 'memory', 'redis', or 'database'")
        if backend == "memory" and environment != "development":
            raise ConfigError(
                "stores.backend = 'memory' is only permitted with "
                "environment = 'development'")
        if backend == "redis" and "redis_url_env" not in st:
            raise ConfigError("stores: backend 'redis' requires redis_url_env")
        if backend == "database" and "postgres_dsn_env" not in st:
            raise ConfigError(
                "stores: backend 'database' requires postgres_dsn_env")
        stores = StoresConfig(
            backend=backend,
            redis_url=_env(st, "redis_url_env", "stores"),
            postgres_dsn=_env(st, "postgres_dsn_env", "stores"),
            schema=text(st["schema"], "stores.schema", 63)
            if "schema" in st else None,
            prefix=text(st["prefix"], "stores.prefix", 128)
            if "prefix" in st else None,
        )

    key_seed = None
    if "key" in t:
        kt = table(t["key"], "key", (), ("seed_file",))
        if "seed_file" in kt:
            key_seed = file_path(kt["seed_file"], "key.seed_file", base)
    root_seed = None
    if "issuer" in t:
        it = table(t["issuer"], "issuer", ("root_seed_file",))
        root_seed = file_path(it["root_seed_file"],
                              "issuer.root_seed_file", base)

    sections, required_peers = _REQUIREMENTS[role]
    if missing := sections - set(t):
        raise ConfigError(
            f"role {role!r} requires sections {sorted(missing)}")
    if missing := required_peers - set(peers):
        raise ConfigError(
            f"role {role!r} requires peers {sorted(missing)}")

    return NodeConfig(
        path=path, role=role,
        spiffe_id=spiffe(t["spiffe_id"], "spiffe_id"),
        environment=environment, tls=tls, governance=governance,
        listen=listen, peers=peers, stores=stores,
        key_seed_file=key_seed, root_seed_file=root_seed,
    )



def _canonical_key_b64(value: Any, where: str) -> str:
    s = text(value, where, 4096).strip()
    while s.startswith("base64:"):
        s = s[len("base64:"):]
    core = s.rstrip("=")
    padded = core + "=" * (-len(core) % 4)
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decode(padded)
        except Exception:
            continue
        if len(raw) != cc.PUBLIC_KEY_BYTES:
            raise ConfigError(
                f"{where}: expected {cc.PUBLIC_KEY_BYTES} bytes, "
                f"got {len(raw)}")
        return cc.b64e(raw)
    raise ConfigError(f"{where}: invalid base64")



def compile_document(source: Mapping[str, Any]) -> dict:
    # FIX: "enrollment" added to optional set
    s = table(source, "governance",
              ("version", "not_before", "expires_at",
               "trust", "policy", "pricing"),
              ("issuance", "enrollment"))
    trust = table(s["trust"], "trust", ("roots",), ("enrollment",))
    pol = table(s["policy"], "policy", ("max_depth", "edges"),
                ("models", "peer_bound_tools"))
    pricing = table(s["pricing"], "pricing", ("rules",), ("default",))

    doc = {
        "format": BUNDLE_FORMAT,
        "version": s["version"],
        "nbf": epoch(s["not_before"], "not_before"),
        "exp": epoch(s["expires_at"], "expires_at"),
        "roots": [
            {
                "issuer": r["issuer"],
                # FIX: canonicalize each key (accepts legacy padded form)
                "keys": sorted(
                    _canonical_key_b64(k, f"trust.roots[{i}].keys[{j}]")
                    for j, k in enumerate(
                        texts(r["keys"], f"trust.roots[{i}].keys"))
                ),
            }
            for i, r in enumerate(tables(
                trust["roots"], "trust.roots",
                ("issuer", "keys"), max_items=64))
        ],
        "policy": {
            "max_depth": pol["max_depth"],
            "models": sorted(
                _model(v, f"policy.models[{i}]")
                for i, v in enumerate(texts(
                    pol.get("models", [cc.Model.KEY_BOUND]),
                    "policy.models"))
            ),
            "peer_bound_tools": sorted(
                texts(pol.get("peer_bound_tools", []),
                      "policy.peer_bound_tools")),
            "edges": [
                {
                    "parent": e["parent"], "child": e["child"],
                    "max_ttl": e["max_ttl"],
                    "max_children": e.get("max_children", 32),
                    "ceiling": _scope(e["ceiling"],
                                      f"policy.edges[{i}].ceiling").to_body(),
                }
                for i, e in enumerate(tables(
                    pol["edges"], "policy.edges",
                    ("parent", "child", "max_ttl", "ceiling"),
                    ("max_children",)))
            ],
        },
        "issuance": [
            {
                "holder": r["holder"],
                "ttl": r["ttl"],
                "max_depth": r.get("max_depth", 1),
                "model": _model(r.get("model", cc.Model.KEY_BOUND),
                                f"issuance[{i}].model"),
                "scope": _scope(r["scope"],
                                f"issuance[{i}].scope").to_body(),
            }
            for i, r in enumerate(tables(
                s.get("issuance", []), "issuance",
                ("holder", "ttl", "scope"), ("max_depth", "model")))
        ],
        "pricing": {
            "rules": [
                _compile_cost(r, f"pricing.rules[{i}]", with_tool=True)
                for i, r in enumerate(
                    pricing["rules"] if isinstance(pricing["rules"], list)
                    else _bad_list("pricing.rules"))
            ],
            "default": (_compile_cost(pricing["default"], "pricing.default",
                                      with_tool=False)
                        if "default" in pricing else None),
        },
    }

    # FIX: canonical enrollment authority key + optional constraint table
    if "enrollment" in trust:
        doc["enrollment_authority"] = _canonical_key_b64(
            trust["enrollment"], "trust.enrollment")

    if s.get("enrollment"):
        t = table(s["enrollment"], "enrollment",
                  ("may_enroll", "ttl", "model", "ceiling"))
        doc["enrollment"] = {
            "may_enroll": t["may_enroll"],
            "ttl":        t["ttl"],
            "model":      _model(t["model"], "enrollment.model"),
            "ceiling":    _scope(t["ceiling"],
                                 "enrollment.ceiling").to_body(),
        }

    body = _encode(doc)
    parse_document(cc.decode(body), _digest(body))
    return doc


# ── parse (canonical document → runtime objects) ────────────────────────

def parse_document(doc: Mapping[str, Any], digest: str) -> Governance:
    d = table(doc, "bundle",
              ("format", "version", "nbf", "exp", "roots",
               "policy", "issuance", "pricing"),
              ("enrollment_authority", "enrollment"))

    if d["format"] != BUNDLE_FORMAT:
        raise ConfigError(f"unsupported bundle format {d['format']!r}")
    version = integer(d["version"], "version", lo=1)
    nbf, exp = integer(d["nbf"], "nbf"), integer(d["exp"], "exp")

    if not nbf < exp <= nbf + MAX_BUNDLE_LIFETIME:
        raise ConfigError(
            "validity window must be positive and at most 90 days")

    # trust roots
    issuers: dict[str, list[bytes]] = {}
    for i, r in enumerate(tables(
            d["roots"], "roots", ("issuer", "keys"), max_items=64)):
        issuer = spiffe(r["issuer"], f"roots[{i}].issuer")
        if issuer in issuers:
            raise ConfigError(f"roots[{i}]: duplicate issuer {issuer}")
        try:
            issuers[issuer] = [
                cc.b64d(k)
                for k in texts(r["keys"], f"roots[{i}].keys", 8)
            ]
        except cc.RejectError:
            raise ConfigError(
                f"roots[{i}].keys: invalid base64") from None

    # enrollment authority (single key)
    raw_ea = d.get("enrollment_authority")
    if raw_ea is None:
        enrollment_key = b""
    else:
        try:
            enrollment_key = cc.b64d(
                text(raw_ea, "enrollment_authority"))
        except cc.RejectError:
            raise ConfigError(
                "enrollment_authority: invalid base64") from None
        if len(enrollment_key) != cc.PUBLIC_KEY_BYTES:
            raise ConfigError(
                f"enrollment_authority: expected "
                f"{cc.PUBLIC_KEY_BYTES} bytes")

    try:
        roots = cc.TrustedRoots(enrollment_key, issuers)
    except ValueError as exc:
        raise ConfigError(f"roots: {exc}") from None

    # delegation policy
    p = table(d["policy"], "policy",
              ("max_depth", "models", "peer_bound_tools", "edges"))
    raw_edges = tables(
        p["edges"], "policy.edges",
        ("parent", "child", "max_ttl", "max_children", "ceiling"),
        max_items=MAX_EDGES)
    edges: list[EdgeRule] = []
    for i, e in enumerate(raw_edges):
        w = f"policy.edges[{i}]"
        try:
            edges.append(EdgeRule(
                parent=spiffe(e["parent"], f"{w}.parent", pattern=True),
                child=spiffe(e["child"], f"{w}.child", pattern=True),
                ceiling=_scope(e["ceiling"], f"{w}.ceiling"),
                max_ttl=integer(e["max_ttl"], f"{w}.max_ttl",
                                lo=1, hi=86400),
                max_children=integer(e["max_children"], f"{w}.max_children",
                                     lo=1, hi=4096),
            ))
        except ValueError as exc:
            raise ConfigError(f"{w}: {exc}") from None

    if _has_cycle(edges):
        raise ConfigError(
            "policy.edges contains a cycle; delegation chains would be "
            "ambiguous (e.g. A → B → A).")

    try:
        policy = Policy(
            version=version,
            root_issuers=frozenset(issuers),
            edges=tuple(edges),
            max_depth=integer(p["max_depth"], "policy.max_depth",
                              hi=cc.MAX_BLOCKS - 1),
            allowed_models=frozenset(
                _model(v, f"policy.models[{i}]")
                for i, v in enumerate(texts(p["models"], "policy.models"))),
            peer_bound_tools=frozenset(
                texts(p["peer_bound_tools"], "policy.peer_bound_tools")),
        )
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"policy: {exc}") from None

    # issuance
    rules: list[IssuanceRule] = []
    for i, r in enumerate(tables(
            d["issuance"], "issuance",
            ("holder", "ttl", "max_depth", "model", "scope"))):
        w = f"issuance[{i}]"
        rules.append(IssuanceRule(
            holder=spiffe(r["holder"], f"{w}.holder", pattern=True),
            scope=_scope(r["scope"], f"{w}.scope"),
            ttl=integer(r["ttl"], f"{w}.ttl", lo=1, hi=86400),
            max_depth=integer(r["max_depth"], f"{w}.max_depth",
                              hi=cc.MAX_BLOCKS - 1),
            model=_model(r["model"], f"{w}.model"),
        ))
    issuance = IssuanceRules(tuple(rules))

    # enrollment (optional)
    raw_enroll = d.get("enrollment")
    if raw_enroll is None:
        enrollment: EnrollmentRule | None = None
    else:
        if not enrollment_key:
            raise ConfigError(
                "enrollment: constraints present but no enrollment_authority "
                "key is pinned")
        t = table(raw_enroll, "enrollment",
                  ("may_enroll", "ttl", "model", "ceiling"))
        enrollment = EnrollmentRule(
            may_enroll=spiffe(t["may_enroll"], "enrollment.may_enroll",
                              pattern=True),
            ceiling=_scope(t["ceiling"], "enrollment.ceiling"),
            ttl=integer(t["ttl"], "enrollment.ttl", lo=1, hi=86400),
            model=_model(t["model"], "enrollment.model"),
        )

    # pricing
    pr = table(d["pricing"], "pricing", ("rules", "default"))
    cost_rules: list[CostRule] = []
    for i, r in enumerate(
            pr["rules"] if isinstance(pr["rules"], list)
            else _bad_list("pricing.rules")):
        tool, tc = _parse_cost(r, f"pricing.rules[{i}]", with_tool=True)
        cost_rules.append(CostRule(tool, tc)) # type: ignore
    default = (None if pr["default"] is None
               else _parse_cost(pr["default"], "pricing.default",
                                with_tool=False)[1])
    try:
        cost = StaticCostModel(cost_rules, default=default)
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"pricing: {exc}") from None

    _cross_check(policy, issuance, enrollment, cost)
    return Governance(version, nbf, exp, digest, roots, policy,
                      cost, issuance, enrollment)




def _cross_check(policy: Policy, issuance: IssuanceRules,
                 enrollment: EnrollmentRule | None,
                 cost: StaticCostModel) -> None:

    """Reject documents that would be internally inconsistent at runtime."""

    if policy.peer_bound_tools and cc.Model.PEER_BOUND not in policy.allowed_models:
        raise ConfigError(
            "policy: peer_bound_tools requires the 'peer_bound' model")

    scopes = [(f"policy.edges[{i}].ceiling", e.ceiling)
              for i, e in enumerate(policy.edges)]
    scopes += [(f"issuance[{i}].scope", r.scope)
               for i, r in enumerate(issuance.rules)]
    if enrollment is not None:
        scopes.append(("enrollment.ceiling", enrollment.ceiling))

    for where, scope in scopes:
        if cc.ANY in scope.tools:
            if not cost.covers_any():
                raise ConfigError(
                    f"{where}: scope permits any tool ('*') but pricing "
                    f"has no `default` rule")
        else:
            for tool in scope.tools:
                if not cost.covers(tool):
                    raise ConfigError(
                        f"{where}: tool {tool!r} has no pricing rule")

    for i, rule in enumerate(issuance.rules):
        w = f"issuance[{i}]"
        if rule.model not in policy.allowed_models:
            raise ConfigError(
                f"{w}: model {rule.model!r} is not allowed by policy")
        if rule.max_depth > policy.max_depth:
            raise ConfigError(
                f"{w}: max_depth exceeds policy.max_depth")
        if rule.holder.endswith("/*"):
            continue
        if not any(
            (edge := policy.edge(root, rule.holder)) is not None
            and rule.scope.is_subset_of(edge.ceiling)
            and rule.ttl <= edge.max_ttl
            for root in policy.root_issuers
        ):
            raise ConfigError(
                f"{w}: no root edge to {rule.holder} whose ceiling and "
                f"max_ttl cover this rule")

    if enrollment is not None:
        if enrollment.model not in policy.allowed_models:
            raise ConfigError(
                f"enrollment: model {enrollment.model!r} is not allowed "
                f"by policy")





def _require_32(raw: bytes) -> bytes:
    if len(raw) != KEY_BYTES:
        raise ValueError(
            f"ed25519 public key must be {KEY_BYTES} bytes, got {len(raw)}")
    return raw


def _decode_inline(s: str, *, where: str) -> bytes:
    # FIX: strip any number of "base64:" prefixes, then try both alphabets
    while s.startswith("base64:"):
        s = s[len("base64:"):]

    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            return _require_32(bytes.fromhex(s))
        except ValueError:
            pass

    core = s.rstrip("=")
    padded = core + "=" * (-len(core) % 4)
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return _require_32(decode(padded))
        except Exception:
            continue

    raise ValueError(
        f"{where}: cannot decode as b64 (urlsafe or standard) or hex "
        f"({len(s)} chars after stripping tags)")


def load_raw(source: str | bytes | Path) -> bytes:
    if isinstance(source, bytes):
        return _require_32(source)

    s = str(source)
    looks_like_path = (
        isinstance(source, Path)
        or s.endswith(_PATH_HINTS)
        or "/" in s
        or "\\" in s
    )

    if looks_like_path:
        p = Path(source)
        if not p.exists():
            raise ValueError(f"key file not found: {p}")
        if not p.is_file():
            raise ValueError(f"not a regular file: {p}")
        raw = p.read_bytes()
        if len(raw) == KEY_BYTES:
            return raw
        try:
            t = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ValueError(
                f"{p}: not a raw {KEY_BYTES}-byte key "
                f"(file is {len(raw)} bytes, not ASCII)") from None
        return _decode_inline(t, where=str(p))

    return _decode_inline(s.strip(), where="<inline>")


def _validated_keys(keys: Iterable[bytes], where: str) -> list[bytes]:
    out: list[bytes] = []
    for i, k in enumerate(keys):
        raw = bytes(k) if isinstance(k, (bytes, bytearray)) else k
        if (not isinstance(raw, bytes)
                or len(raw) != cc.PUBLIC_KEY_BYTES):
            raise ConfigError(
                f"{where}[{i}]: expected "
                f"{cc.PUBLIC_KEY_BYTES} bytes")
        out.append(raw)
    if not out:
        raise ConfigError(f"{where}: at least one key required")
    return out


def sign_bundle(doc: Mapping[str, Any], key: cc.CapChainKey) -> bytes:
    """Sign a bundle with a single authority key."""
    body = _encode(doc)
    if len(body) > MAX_BUNDLE_BYTES:
        raise ConfigError("bundle body too large")
    parse_document(cc.decode(body), _digest(body))
    return _encode_envelope({
        "format": BUNDLE_FORMAT,
        "key": cc.b64e(key.public_key),
        "sig": cc.b64e(key.sign(CTX_GOVERNANCE, body)),
        "body": cc.b64e(body),
    })


def sign_bundle_with_rotation(
    doc: Mapping[str, Any],
    current_key: cc.CapChainKey,
    next_key: cc.CapChainKey,
) -> bytes:
    """Sign a bundle with TWO authority keys during a rotation window.

    The envelope carries ``key_next`` and ``sig_next``. Nodes that accept
    this bundle learn the next authority key from the bundle itself, so
    the current authority explicitly approves its own successor.
    """   
    body = _encode(doc)
    if len(body) > MAX_BUNDLE_BYTES:
        raise ConfigError("bundle body too large")
    parse_document(cc.decode(body), _digest(body))
    return _encode_envelope({
        "format": BUNDLE_FORMAT,
        "key": cc.b64e(current_key.public_key),
        "sig": cc.b64e(current_key.sign(CTX_GOVERNANCE, body)),
        "key_next": cc.b64e(next_key.public_key),
        "sig_next": cc.b64e(next_key.sign(CTX_GOVERNANCE, body)),
        "body": cc.b64e(body),
    })


def _open_bundle_full(
    raw: bytes, authority_keys: Iterable[bytes],
) -> tuple[Governance, bytes | None, bytes | None]:
    
    """Verify and parse. Return (governance, signer_public_key, next_public_key).

    Does NOT check liveness or rollback; GovernanceLoader does both.
    """
    keys = _validated_keys(authority_keys, "authority_keys")
    if len(raw) > 2 * MAX_BUNDLE_BYTES:
        raise ConfigError("bundle too large")
    try:
        envelope = json.loads(raw, object_pairs_hook=_no_duplicates)
    except ConfigError:
        raise
    except Exception:
        raise ConfigError("bundle is not valid JSON") from None
    allowed = {"format", "key", "sig", "body", "key_next", "sig_next"}
    if not isinstance(envelope, dict) or set(envelope) - allowed:
        raise ConfigError("bundle envelope has unknown fields")
    table(envelope, "bundle envelope", ("format", "key", "sig", "body"),
          ("key_next", "sig_next"))
    if envelope["format"] != BUNDLE_FORMAT:
        raise ConfigError(
            f"unsupported bundle format {envelope['format']!r}")

    has_next = "key_next" in envelope or "sig_next" in envelope
    if has_next and not ("key_next" in envelope and "sig_next" in envelope):
        raise ConfigError("bundle envelope has a partial rotation signature")

    try:
        public_key = cc.b64d(envelope["key"])
        signature = cc.b64d(envelope["sig"])
        body = cc.b64d(envelope["body"])
        next_pk = (cc.b64d(envelope["key_next"])
                   if has_next else None)
        next_sig = (cc.b64d(envelope["sig_next"])
                    if has_next else None)
    except cc.RejectError:
        raise ConfigError("bundle envelope has invalid base64") from None
    if len(body) > MAX_BUNDLE_BYTES:
        raise ConfigError("bundle body too large")
    if not any(hmac.compare_digest(public_key, k) for k in keys):
        raise ConfigError(
            "bundle is signed by a key that is not a pinned governance "
            "authority")

    try:
        cc.verify_signature(public_key, signature, CTX_GOVERNANCE, body,
                            cc.Code.POLICY_DENIED, "governance bundle")
    except cc.RejectError:
        raise ConfigError("bundle signature is invalid") from None

    if has_next:
        if (not isinstance(next_pk, bytes)
                or len(next_pk) != cc.PUBLIC_KEY_BYTES):
            raise ConfigError("rotation: next key has wrong length")
        try:
            cc.verify_signature(next_pk, next_sig, CTX_GOVERNANCE, body, # type: ignore
                                cc.Code.POLICY_DENIED,
                                "governance bundle (next)")
        except cc.RejectError:
            raise ConfigError(
                "bundle next-key signature is invalid") from None

    try:
        doc = cc.decode(body)
    except cc.RejectError as exc:
        raise ConfigError(
            f"bundle body is not canonical: "
            f"{exc.detail or exc.code}") from None
    return parse_document(doc, _digest(body)), public_key, next_pk


def open_bundle(raw: bytes, authority_keys: Iterable[bytes]) -> Governance:
    """Verify and parse. Return the Governance only (backward-compatible)."""
    gov, _, _ = _open_bundle_full(raw, authority_keys)
    return gov


def open_bundle_with_signer(
    raw: bytes, authority_keys: Iterable[bytes],
) -> tuple[Governance, bytes | None, bytes | None]:
    """Verify and parse. Return (governance, signer_pk, next_pk).

    ``signer_pk`` may be None if the caller only wants Governance and
    does not need to distinguish current from previous authority keys.
    ``next_pk`` is present when the envelope carries a rotation signature.
    """
    return _open_bundle_full(raw, authority_keys)




def thumbprint(raw: bytes) -> str:
    _require_32(raw)
    return hashlib.sha256(raw).hexdigest()

