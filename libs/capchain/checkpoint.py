"""Async state protocols and implementations.

The in-memory classes are for development and tests. Production deployments
must supply durable, shared implementations (Postgres, Redis) of the same
protocols; otherwise replay protection and budgets are per-process only.

    stores = await Stores.open("memory")                     # tests
    stores = await Stores.open("redis", redis_url=...)       # all five in Redis
    stores = await Stores.open("database", postgres_dsn=...) # all five in PostgreSQL
    stores = await Stores.from_env()                         # per-store type

Production, when more than one gateway process is running:

    replay=redis  revocation=redis  enrollments=redis
    ledger=postgres  evidence=postgres

Only the issuer and the gateways open a Stores. Agent containers do not:
delegation and proof-of-possession are signatures, not database calls.

    Gateway(..., **stores.as_gateway_kwargs())
    TokenIssuer(..., **stores.as_issuer_kwargs())

Env:
    CAPCHAIN_ENV=production          memory is refused; Redis policy is checked
    CAPCHAIN_STORE=redis             default type for every store
    CAPCHAIN_STORE_REPLAY=redis      override one store
    CAPCHAIN_REDIS_URL=redis://redis:6379/0
    CAPCHAIN_POSTGRES_DSN=postgresql://capchain@postgres/capchain
    CAPCHAIN_REDIS_PREFIX=capchain
    CAPCHAIN_POSTGRES_SCHEMA=capchain
    CAPCHAIN_REPLAY_TTL=300          must be > 2 x PoP skew
    CAPCHAIN_ENROLL_TTL=3600
    CAPCHAIN_ENROLL_MAX_PER_PEER=8

Redis: maxmemory-policy noeviction. A Redis ledger also needs AOF
(appendonly yes); PostgreSQL is the ledger you want.

Requires Python 3.10+ (parenthesized async with, PEP 617).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from .capchain import (
    GENESIS_HASH,
    BudgetPath,
    Code,
    RejectError,
    encode,
    decode,
)


_log = logging.getLogger("capchain.store")

TYPES = {"memory", "postgres", "redis"}
_ALIASES = {
    "mem": "memory",
    "memory": "memory",
    "redis": "redis",
    "postgres": "postgres",
    "postgresql": "postgres",
    "database": "postgres",
    "db": "postgres",
}
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_GENESIS = "0" * 64
_SOCKET_TIMEOUT = 5.0
_STATEMENT_TIMEOUT_MS = 5000


def _kind(value: str) -> str:
    kind = _ALIASES.get(value.strip().lower())
    if kind is None:
        raise ValueError(f"unknown store type {value!r}; use memory, database, or redis")
    return kind


def _ident(name: str, value: str) -> str:
    if not _IDENT.fullmatch(value):
        raise ValueError(f"bad {name}")
    return value


def _now() -> int:
    return int(time.time())


def _budget_tag(cid: str) -> str:
    return hashlib.sha256(cid.encode()).hexdigest()[:16]


def _replay_key(prefix: str, key: tuple[str, ...]) -> str:
    body = ":".join(f"{len(part)}:{part}" for part in key)
    return f"{prefix}:replay:{body}"


@dataclass(frozen=True, slots=True)
class StoreSpec:
    type: str
    redis_url: str | None = None
    postgres_dsn: str | None = None
    prefix: str = "capchain"
    schema: str = "capchain"
    ttl_seconds: int | None = None
    max_per_peer: int = 8


class ReservationState:
    RESERVED = "reserved"
    DISPATCHED = "dispatched"
    SETTLED = "settled"
    CANCELLED = "cancelled"


@dataclass(slots=True)
class SpendHandle:
    cid: str
    amount: int
    handle: str
    path: BudgetPath
    state: str = ReservationState.RESERVED


@dataclass(frozen=True, slots=True)
class Evidence:
    """One immutable audit record.

    On an admission record, `cost_micros` is the reservation. The settled
    amount appears on a follow-up SETTLED record linked by `related_id`.
    """

    action_id: str
    code: str
    cid: str
    jtis: tuple[str, ...]
    peer_id: str
    issuer: str
    holder: str
    action: str
    resource: str
    payload_hash: str
    cost_micros: int
    ts: int
    pop_thumbprint: str
    channel_bound: bool
    prev_hash: str
    verifier: str = ""
    related_id: str = ""

    def digest(self) -> str:
        return hashlib.sha256(
            encode(
                {
                    "action_id": self.action_id,
                    "code": self.code,
                    "cid": self.cid,
                    "jtis": list(self.jtis),
                    "peer_id": self.peer_id,
                    "issuer": self.issuer,
                    "holder": self.holder,
                    "action": self.action,
                    "resource": self.resource,
                    "payload_hash": self.payload_hash,
                    "cost_micros": self.cost_micros,
                    "ts": self.ts,
                    "pop_thumbprint": self.pop_thumbprint,
                    "channel_bound": self.channel_bound,
                    "prev_hash": self.prev_hash,
                    "verifier": self.verifier,
                    "related_id": self.related_id,
                }
            )
        ).hexdigest()



# ---------------------------------------------------------------------------
# Protocols (all async)
# ---------------------------------------------------------------------------

class EnrollmentStore(Protocol):
    """Bindings from workload identity to enrolled key thumbprint."""

    async def add(self, peer_id: str, key_thumbprint: str, now: int) -> None: ...
    async def require(self, peer_id: str, key_thumbprint: str, now: int) -> None: ...


class ReplayStore(Protocol):
    """Single-use nonce store. `ttl_seconds` must exceed 2x the PoP skew."""

    @property
    def ttl_seconds(self) -> int: ...
    async def consume(self, key: tuple[str, ...], now: int) -> bool: ...


class BudgetLedger(Protocol):
    async def reserve(
        self,
        cid: str,
        root_cap: int,
        path: BudgetPath,
        amount: int,
        *,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> SpendHandle | None: ...

    async def mark_dispatched(self, handle: SpendHandle) -> None: ...
    async def settle(self, handle: SpendHandle, actual: int) -> None: ...
    async def commit(self, handle: SpendHandle) -> None: ...
    async def refund(self, handle: SpendHandle) -> None: ...
    async def remaining(self, cid: str) -> int: ...


class RevocationStore(Protocol):
    async def revoke_agent(self, value: str) -> None: ...
    async def revoke_key(self, value: str) -> None: ...
    async def revoke_chain(self, value: str) -> None: ...
    async def revoke_token(self, value: str) -> None: ...
    async def find_revoked(
        self,
        *,
        agents: tuple[str, ...] = (),
        kids: tuple[str, ...] = (),
        cids: tuple[str, ...] = (),
        jtis: tuple[str, ...] = (),
    ) -> tuple[str, str] | None: ...


class EvidenceStore(Protocol):
    async def append(self, draft: dict) -> Evidence: ...
    async def verify_integrity(self) -> bool: ...
    async def records(self) -> tuple[Evidence, ...]: ...


# ---------------------------------------------------------------------------
# In-memory implementations (async, asyncio.Lock)
# ---------------------------------------------------------------------------

class InMemoryEnrollments:
    """Development enrollment store with a fixed TTL."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._entries: dict[tuple[str, str], int] = {}
        self._lock = asyncio.Lock()

    async def add(self, peer_id: str, key_thumbprint: str, now: int) -> None:
        async with self._lock:
            self._entries[(peer_id, key_thumbprint)] = now + self._ttl

    async def require(self, peer_id: str, key_thumbprint: str, now: int) -> None:
        async with self._lock:
            expires_at = self._entries.get((peer_id, key_thumbprint))
        if expires_at is None or expires_at <= now:
            raise RejectError(Code.NOT_ENROLLED, "key not enrolled for this identity")


class InMemoryReplayStore:
    """Development nonce store. Not shared across processes."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = ttl_seconds
        self._live: dict[tuple[str, ...], int] = {}
        self._lock = asyncio.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    async def consume(self, key: tuple[str, ...], now: int) -> bool:
        async with self._lock:
            if len(self._live) > 10_000:
                self._live = {k: e for k, e in self._live.items() if e > now}
            expires_at = self._live.get(key)
            if expires_at is not None and expires_at > now:
                return False
            self._live[key] = now + self._ttl
            return True


class InMemoryBudgetLedger:
    """Development ledger. Enforces root and per-hop caps under one lock."""

    EVICT_ABOVE: int = 10_000

    def __init__(self) -> None:
        self._root_cap: dict[str, int] = {}
        self._remaining: dict[str, int] = {}
        self._hop_cap: dict[tuple[str, str], int] = {}
        self._hop_spent: dict[tuple[str, str], int] = {}
        self._outstanding: dict[str, SpendHandle] = {}
        self._expires_at: dict[str, int] = {}
        self._lock = asyncio.Lock()

    def _purge_locked(self, now: int) -> int:
        outstanding_cids = {h.cid for h in self._outstanding.values()}
        dead = [
            cid
            for cid, exp in self._expires_at.items()
            if (exp <= now
                and cid not in outstanding_cids
                and self._remaining.get(cid, 0) == self._root_cap.get(cid, 0))
        ]
        if not dead:
            return 0
        for cid in dead:
            self._expires_at.pop(cid, None)
            self._root_cap.pop(cid, None)
            self._remaining.pop(cid, None)
        live = self._root_cap.keys()
        self._hop_cap = {k: v for k, v in self._hop_cap.items() if k[0] in live}
        self._hop_spent = {k: v for k, v in self._hop_spent.items() if k[0] in live}
        return len(dead)

    async def purge_expired(self, now: int) -> int:
        async with self._lock:
            return self._purge_locked(now)

    async def remaining(self, cid: str) -> int:
        async with self._lock:
            return self._remaining.get(cid, 0)

    async def reserve(
        self,
        cid: str,
        root_cap: int,
        path: BudgetPath,
        amount: int,
        *,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> SpendHandle | None:
        if (
            type(amount) is not int
            or type(root_cap) is not int
            or amount < 0
            or root_cap < 0
            or not path
        ):
            raise ValueError("bad reserve arguments")

        async with self._lock:
            if now is not None and len(self._root_cap) > self.EVICT_ABOVE:
                self._purge_locked(now)

            existing = self._root_cap.get(cid)
            if existing is not None and existing != root_cap:
                raise RejectError(Code.BUDGET_CAP_CHANGED, f"cid {cid}")

            remaining = self._remaining.get(cid, root_cap)
            if remaining < amount:
                return None

            for jti, cap in path:
                if type(cap) is not int or cap < 0:
                    raise ValueError("bad hop cap")
                recorded = self._hop_cap.get((cid, jti))
                if recorded is not None and recorded != cap:
                    raise RejectError(Code.BUDGET_CAP_CHANGED, f"jti {jti}")
                spent = self._hop_spent.get((cid, jti), 0)
                if spent + amount > cap:
                    return None

            self._root_cap.setdefault(cid, root_cap)
            self._remaining[cid] = remaining - amount
            if expires_at is not None:
                self._expires_at.setdefault(cid, expires_at)
            for jti, cap in path:
                key = (cid, jti)
                self._hop_cap.setdefault(key, cap)
                self._hop_spent[key] = self._hop_spent.get(key, 0) + amount

            handle = SpendHandle(
                cid=cid,
                amount=amount,
                handle=uuid.uuid4().hex,
                path=path,
            )
            self._outstanding[handle.handle] = handle
            return handle

    async def mark_dispatched(self, handle: SpendHandle) -> None:
        async with self._lock:
            record = self._outstanding.get(handle.handle)
            if record is None or record.state != ReservationState.RESERVED:
                raise RejectError(Code.INTERNAL, "dispatch from invalid state")
            record.state = handle.state = ReservationState.DISPATCHED

    async def settle(self, handle: SpendHandle, actual: int) -> None:
        if type(actual) is not int or actual < 0:
            raise RejectError(Code.INTERNAL, "actual must be a non-negative int")

        async with self._lock:
            record = self._outstanding.get(handle.handle)
            if record is None:
                raise RejectError(Code.INTERNAL, "settle: handle not found")
            if record.state != ReservationState.DISPATCHED:
                raise RejectError(
                    Code.INTERNAL,
                    f"settle from {record.state}; call mark_dispatched first",
                )
            delta = actual - record.amount
            if delta != 0:
                if self._remaining[record.cid] - delta < 0:
                    raise RejectError(Code.BUDGET_EXHAUSTED, "root cap on settle")
                updated: dict[tuple[str, str], int] = {}
                for jti, cap in record.path:
                    spent = self._hop_spent.get((record.cid, jti), 0) + delta
                    if spent < 0 or spent > cap:
                        raise RejectError(Code.BUDGET_EXHAUSTED, f"hop {jti} on settle")
                    updated[(record.cid, jti)] = spent
                self._remaining[record.cid] -= delta
                self._hop_spent.update(updated)
                record.amount = actual
            record.state = ReservationState.SETTLED
            handle.amount, handle.state = record.amount, record.state

    async def commit(self, handle: SpendHandle) -> None:
        async with self._lock:
            self._outstanding.pop(handle.handle, None)

    async def refund(self, handle: SpendHandle) -> None:
        async with self._lock:
            record = self._outstanding.get(handle.handle)
            if record is None or record.state != ReservationState.RESERVED:
                return
            self._outstanding.pop(handle.handle, None)
            self._remaining[record.cid] = (
                self._remaining.get(record.cid, 0) + record.amount
            )
            for jti, _ in record.path:
                key = (record.cid, jti)
                self._hop_spent[key] = max(
                    0,
                    self._hop_spent.get(key, 0) - record.amount,
                )
            handle.state = ReservationState.CANCELLED


class InMemoryRevocationStore:
    def __init__(self) -> None:
        self._agents: set[str] = set()
        self._kids: set[str] = set()
        self._cids: set[str] = set()
        self._jtis: set[str] = set()
        self._lock = asyncio.Lock()

    async def revoke_agent(self, value: str) -> None:
        async with self._lock:
            self._agents.add(value)

    async def revoke_key(self, value: str) -> None:
        async with self._lock:
            self._kids.add(value)

    async def revoke_chain(self, value: str) -> None:
        async with self._lock:
            self._cids.add(value)

    async def revoke_token(self, value: str) -> None:
        async with self._lock:
            self._jtis.add(value)

    async def find_revoked(
        self,
        *,
        agents: tuple[str, ...] = (),
        kids: tuple[str, ...] = (),
        cids: tuple[str, ...] = (),
        jtis: tuple[str, ...] = (),
    ) -> tuple[str, str] | None:
        async with self._lock:
            for kind, candidates, revoked in (
                ("agent", agents, self._agents),
                ("kid", kids, self._kids),
                ("cid", cids, self._cids),
                ("jti", jtis, self._jtis),
            ):
                for candidate in candidates:
                    if candidate in revoked:
                        return (kind, candidate)
        return None


class InMemoryEvidenceLog:
    def __init__(self) -> None:
        self._head = GENESIS_HASH
        self._records: list[Evidence] = []
        self._lock = asyncio.Lock()

    async def append(self, draft: dict) -> Evidence:
        async with self._lock:
            record = Evidence(
                prev_hash=self._head,
                **{k: v for k, v in draft.items() if k != "prev_hash"},
            )
            self._records.append(record)
            self._head = record.digest()
            return record

    async def verify_integrity(self) -> bool:
        async with self._lock:
            previous = GENESIS_HASH
            for record in self._records:
                if record.prev_hash != previous:
                    return False
                previous = record.digest()
            return previous == self._head

    async def records(self) -> tuple[Evidence, ...]:
        async with self._lock:
            return tuple(self._records)


# ---------------------------------------------------------------------------
# Lua scripts (unchanged — strings)
# ---------------------------------------------------------------------------

_RESERVE_LUA = """
local amount = tonumber(ARGV[1])
local root_cap = tonumber(ARGV[2])
local n = #KEYS - 2
if amount == nil or root_cap == nil or amount < 0 or root_cap < 0 or n < 1 then
  return {'err', 'INTERNAL', 'bad reserve'}
end
if #ARGV ~= 7 + n then
  return {'err', 'INTERNAL', 'hop arity'}
end
local expires_at = tonumber(ARGV[7])
local chain_exists = redis.call('EXISTS', KEYS[1]) == 1
if chain_exists then
  if tonumber(redis.call('HGET', KEYS[1], 'root_cap')) ~= root_cap then
    return {'err', 'BUDGET_CAP_CHANGED', 'cid'}
  end
end
local hop_exists = {}
for i = 1, n do
  local cap = tonumber(ARGV[7 + i])
  if redis.call('EXISTS', KEYS[2 + i]) == 1 then
    hop_exists[i] = 1
    if tonumber(redis.call('HGET', KEYS[2 + i], 'cap')) ~= cap then
      return {'err', 'BUDGET_CAP_CHANGED', 'jti'}
    end
  else
    hop_exists[i] = 0
  end
end
local remaining = root_cap
if chain_exists then
  remaining = tonumber(redis.call('HGET', KEYS[1], 'remaining'))
end
local fits = remaining >= amount
if fits then
  for i = 1, n do
    local spent = 0
    if hop_exists[i] == 1 then
      spent = tonumber(redis.call('HGET', KEYS[2 + i], 'spent'))
    end
    if spent + amount > tonumber(ARGV[7 + i]) then
      fits = false
      break
    end
  end
end
if not chain_exists then
  redis.call('HSET', KEYS[1], 'root_cap', root_cap, 'remaining', root_cap)
end
for i = 1, n do
  if hop_exists[i] == 0 then
    redis.call('HSET', KEYS[2 + i], 'cap', tonumber(ARGV[7 + i]), 'spent', 0)
  end
end
if expires_at ~= nil and expires_at > 0 then
  local ttl = redis.call('TTL', KEYS[1])
  local current_expiry = 0
  if ttl > 0 then
    local t = redis.call('TIME')
    current_expiry = tonumber(t[1]) + ttl
  end
  if expires_at > current_expiry then
    redis.call('EXPIREAT', KEYS[1], expires_at)
    for i = 1, n do
      redis.call('EXPIREAT', KEYS[2 + i], expires_at)
    end
  end
end
if not fits then
  return {'full'}
end
redis.call('HINCRBY', KEYS[1], 'remaining', -amount)
for i = 1, n do
  redis.call('HINCRBY', KEYS[2 + i], 'spent', amount)
end
redis.call('HSET', KEYS[2], 'cid', ARGV[4], 'amount', amount,
           'path', ARGV[5], 'state', 'reserved', 'created_at', ARGV[6])
return {'ok'}
"""

_DISPATCH_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {'err', 'INTERNAL', 'dispatch: bad state'}
end
if redis.call('HGET', KEYS[1], 'state') ~= 'reserved' then
  return {'err', 'INTERNAL', 'dispatch: bad state'}
end
redis.call('HSET', KEYS[1], 'state', 'dispatched')
return {'ok'}
"""

_SETTLE_LUA = """
local actual = tonumber(ARGV[1])
if actual == nil or actual < 0 then
  return {'err', 'INTERNAL', 'actual'}
end
if redis.call('EXISTS', KEYS[2]) == 0 then
  return {'err', 'INTERNAL', 'settle: handle lost'}
end
local state = redis.call('HGET', KEYS[2], 'state')
if state ~= 'dispatched' then
  return {'err', 'INTERNAL', 'settle from ' .. tostring(state)}
end
local reserved = tonumber(redis.call('HGET', KEYS[2], 'amount'))
local delta = actual - reserved
if delta ~= 0 then
  local remaining = tonumber(redis.call('HGET', KEYS[1], 'remaining'))
  if remaining - delta < 0 then
    return {'err', 'BUDGET_EXHAUSTED', 'root on settle'}
  end
  local n = #KEYS - 2
  for i = 1, n do
    local spent = tonumber(redis.call('HGET', KEYS[2 + i], 'spent'))
    local cap = tonumber(redis.call('HGET', KEYS[2 + i], 'cap'))
    local next_spent = spent + delta
    if next_spent < 0 or next_spent > cap then
      return {'err', 'BUDGET_EXHAUSTED', 'hop on settle'}
    end
  end
  redis.call('HINCRBY', KEYS[1], 'remaining', -delta)
  for i = 1, n do
    redis.call('HINCRBY', KEYS[2 + i], 'spent', delta)
  end
end
redis.call('HSET', KEYS[2], 'amount', actual, 'state', 'settled')
return {'ok'}
"""

_REFUND_LUA = """
if redis.call('EXISTS', KEYS[2]) == 0 then
  return {'ok'}
end
if redis.call('HGET', KEYS[2], 'state') ~= 'reserved' then
  return {'ok'}
end
local amount = tonumber(redis.call('HGET', KEYS[2], 'amount'))
redis.call('HINCRBY', KEYS[1], 'remaining', amount)
local n = #KEYS - 2
for i = 1, n do
  local spent = tonumber(redis.call('HGET', KEYS[2 + i], 'spent')) - amount
  if spent < 0 then spent = 0 end
  redis.call('HSET', KEYS[2 + i], 'spent', spent)
end
redis.call('DEL', KEYS[2])
return {'ok'}
"""

_ENROLL_ADD = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
redis.call('ZREM', KEYS[1], ARGV[1])
while redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) do
  redis.call('ZPOPMIN', KEYS[1])
end
redis.call('ZADD', KEYS[1], ARGV[3], ARGV[1])
return 1
"""

_ENROLL_REQUIRE = """
local exp = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not exp then return 0 end
if tonumber(exp) <= tonumber(ARGV[2]) then
  redis.call('ZREM', KEYS[1], ARGV[1])
  return 0
end
return 1
"""


def _lua_reply(raw: object) -> str:
    if not isinstance(raw, (list, tuple)) or not raw:
        raise RejectError(Code.STATE_UNAVAILABLE, "bad redis script reply")
    kind = raw[0]
    if kind in ("ok", "full"):
        return str(kind)
    if kind == "err":
        code = raw[1] if len(raw) > 1 else Code.INTERNAL
        detail = raw[2] if len(raw) > 2 else ""
        raise RejectError(str(code), str(detail))
    raise RejectError(Code.STATE_UNAVAILABLE, "bad redis script reply")


# ---------------------------------------------------------------------------
# Redis implementations (redis.asyncio)
# ---------------------------------------------------------------------------

class RedisReplayStore:
    def __init__(self, client: object, ttl_seconds: int, prefix: str) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._r = client
        self._ttl = ttl_seconds
        self._prefix = prefix

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    async def consume(self, key: tuple[str, ...], now: int) -> bool:
        # `now` is unused: expiry is relative to the server clock.
        del now
        return bool(
            await self._r.set(
                _replay_key(self._prefix, key),
                "1",
                nx=True,
                ex=self._ttl,
            )
        )

    async def ping(self) -> None:
        await self._r.ping()


class RedisBudgetLedger:
    """Atomic per cid. Keys share a hash tag so a Redis Cluster slot holds
    one chain. Prefer Postgres: this survives only the AOF window."""

    def __init__(self, client: object, prefix: str) -> None:
        self._r = client
        self._prefix = prefix
        self._reserve = client.register_script(_RESERVE_LUA)
        self._dispatch = client.register_script(_DISPATCH_LUA)
        self._settle = client.register_script(_SETTLE_LUA)
        self._refund = client.register_script(_REFUND_LUA)

    def _chain(self, cid: str) -> str:
        return f"{self._prefix}:budget:{{{_budget_tag(cid)}}}:chain"

    def _hop(self, cid: str, jti: str) -> str:
        return f"{self._prefix}:budget:{{{_budget_tag(cid)}}}:hop:{jti}"

    def _res(self, cid: str, handle: str) -> str:
        return f"{self._prefix}:budget:{{{_budget_tag(cid)}}}:res:{handle}"

    def _hops(self, cid: str, path: tuple) -> tuple[str, ...]:
        return tuple(self._hop(cid, jti) for jti, _ in _check_path(path))

    async def remaining(self, cid: str) -> int:
        val = await self._r.hget(self._chain(cid), "remaining")
        return int(val) if val is not None else 0

    async def reserve(
        self,
        cid: str,
        root_cap: int,
        path: tuple,
        amount: int,
        *,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> SpendHandle | None:
        if amount < 0 or root_cap < 0:
            raise ValueError("bad reserve args")
        ordered = _check_path(path)
        handle = uuid.uuid4().hex
        keys = (
            self._chain(cid),
            self._res(cid, handle),
            *self._hops(cid, ordered),
        )
        args = [
            amount,
            root_cap,
            handle,
            cid,
            _dump_path(ordered),
            now if now is not None else _now(),
            expires_at if expires_at is not None else 0,
            *[cap for _, cap in ordered],
        ]
        reply = await self._reserve(keys=list(keys), args=args)
        if _lua_reply(reply) == "full":
            return None
        return SpendHandle(cid=cid, amount=amount, handle=handle, path=ordered)

    async def mark_dispatched(self, handle: SpendHandle) -> None:
        reply = await self._dispatch(keys=[self._res(handle.cid, handle.handle)])
        _lua_reply(reply)
        handle.state = ReservationState.DISPATCHED

    async def settle(self, handle: SpendHandle, actual: int) -> None:
        if type(actual) is not int or actual < 0:
            raise RejectError(Code.INTERNAL, "actual must be a non-negative int")
        keys = [
            self._chain(handle.cid),
            self._res(handle.cid, handle.handle),
            *self._hops(handle.cid, handle.path),
        ]
        reply = await self._settle(keys=keys, args=[actual])
        _lua_reply(reply)
        handle.amount = actual
        handle.state = ReservationState.SETTLED

    async def commit(self, handle: SpendHandle) -> None:
        await self._r.delete(self._res(handle.cid, handle.handle))

    async def refund(self, handle: SpendHandle) -> None:
        keys = [
            self._chain(handle.cid),
            self._res(handle.cid, handle.handle),
            *self._hops(handle.cid, handle.path),
        ]
        reply = await self._refund(keys=keys)
        _lua_reply(reply)
        handle.state = ReservationState.CANCELLED

    async def ping(self) -> None:
        await self._r.ping()


class RedisRevocationStore:
    def __init__(self, client: object, prefix: str) -> None:
        self._r = client
        self._prefix = prefix

    def _key(self, kind: str) -> str:
        return f"{self._prefix}:revoked:{kind}"

    async def revoke_agent(self, value: str) -> None:
        await self._r.sadd(self._key("agent"), value)

    async def revoke_key(self, value: str) -> None:
        await self._r.sadd(self._key("kid"), value)

    async def revoke_chain(self, value: str) -> None:
        await self._r.sadd(self._key("cid"), value)

    async def revoke_token(self, value: str) -> None:
        await self._r.sadd(self._key("jti"), value)

    async def find_revoked(
        self,
        *,
        agents: tuple[str, ...] = (),
        kids: tuple[str, ...] = (),
        cids: tuple[str, ...] = (),
        jtis: tuple[str, ...] = (),
    ) -> tuple[str, str] | None:
        pairs = [
            ("agent", agents),
            ("kid", kids),
            ("cid", cids),
            ("jti", jtis),
        ]
        flat: list[tuple[str, str]] = []
        async with self._r.pipeline(transaction=False) as pipe:
            for kind, items in pairs:
                for item in items:
                    pipe.sismember(self._key(kind), item)
                    flat.append((kind, item))
            if not flat:
                return None
            results = await pipe.execute()
        for hit, pair in zip(results, flat, strict=False):
            if hit:
                return pair
        return None

    async def ping(self) -> None:
        await self._r.ping()


class RedisEnrollments:
    def __init__(
        self,
        client: object,
        ttl_seconds: int,
        max_per_peer: int,
        prefix: str,
    ) -> None:
        if ttl_seconds <= 0 or max_per_peer <= 0:
            raise ValueError("ttl_seconds and max_per_peer must be > 0")
        self._r = client
        self._ttl = ttl_seconds
        self._max = max_per_peer
        self._prefix = prefix
        self._add = client.register_script(_ENROLL_ADD)
        self._require = client.register_script(_ENROLL_REQUIRE)

    def _key(self, peer_id: str) -> str:
        return f"{self._prefix}:enroll:{peer_id}"

    async def add(self, peer_id: str, cnf: str, now: int) -> None:
        await self._add(
            keys=[self._key(peer_id)],
            args=[cnf, now, now + self._ttl, self._max],
        )

    async def require(self, peer_id: str, cnf: str, now: int) -> None:
        ok = await self._require(
            keys=[self._key(peer_id)],
            args=[cnf, now],
        )
        if not ok:
            raise RejectError(
                Code.NOT_ENROLLED,
                "key not enrolled for this SPIFFE ID",
            )

    async def revoke(self, peer_id: str, cnf: str | None = None) -> None:
        if cnf is None:
            await self._r.delete(self._key(peer_id))
        else:
            await self._r.zrem(self._key(peer_id), cnf)

    async def ping(self) -> None:
        await self._r.ping()


class RedisEvidenceLog:
    def __init__(self, client: object, prefix: str) -> None:
        import redis.exceptions as _redis_exc

        self._r = client
        self._watch_error = _redis_exc.WatchError
        self._head = f"{prefix}:evidence:head"
        self._log = f"{prefix}:evidence:log"

    async def append(self, draft: dict) -> Evidence:
        for _ in range(8):
            async with self._r.pipeline() as pipe:
                try:
                    await pipe.watch(self._head)
                    head = await pipe.get(self._head) or _GENESIS
                    ev = _evidence(draft, head)
                    pipe.multi()
                    pipe.rpush(self._log, _dump_evidence(ev))
                    pipe.set(self._head, ev.digest())
                    await pipe.execute()
                    return ev
                except self._watch_error:
                    continue
        raise RejectError(Code.STATE_UNAVAILABLE, "evidence contention")

    async def verify_integrity(self) -> bool:
        prev = _GENESIS
        for raw in await self._r.lrange(self._log, 0, -1):
            ev = _load_evidence(raw)
            if _dump_evidence(ev) != raw:
                return False
            if ev.prev_hash != prev:
                return False
            prev = ev.digest()
        head = await self._r.get(self._head) or _GENESIS
        return prev == head

    async def records(self) -> tuple[Evidence, ...]:
        rows = await self._r.lrange(self._log, 0, -1)
        return tuple(_load_evidence(raw) for raw in rows)

    async def ping(self) -> None:
        await self._r.ping()


# ---------------------------------------------------------------------------
# PostgreSQL schema (unchanged)
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS replay_nonces (
    key TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS budget_chains (
    cid TEXT PRIMARY KEY,
    expires_at BIGINT,
    root_cap BIGINT NOT NULL CHECK (root_cap >= 0),
    remaining BIGINT NOT NULL CHECK (remaining >= 0)
);
CREATE TABLE IF NOT EXISTS budget_hops (
    cid TEXT NOT NULL REFERENCES budget_chains(cid),
    jti TEXT NOT NULL,
    cap BIGINT NOT NULL CHECK (cap >= 0),
    spent BIGINT NOT NULL CHECK (spent >= 0),
    PRIMARY KEY (cid, jti),
    CHECK (spent <= cap)
);
CREATE TABLE IF NOT EXISTS budget_reservations (
    handle TEXT PRIMARY KEY,
    cid TEXT NOT NULL REFERENCES budget_chains(cid),
    amount BIGINT NOT NULL CHECK (amount >= 0),
    path_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'dispatched', 'settled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS budget_reservations_reap
    ON budget_reservations (created_at) WHERE state = 'reserved';
CREATE TABLE IF NOT EXISTS revocations (
    kind TEXT NOT NULL CHECK (kind IN ('agent', 'kid', 'cid', 'jti')),
    value TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE TABLE IF NOT EXISTS evidence_head (
    id INT PRIMARY KEY CHECK (id = 1),
    head TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    seq BIGSERIAL PRIMARY KEY,
    prev_hash TEXT NOT NULL UNIQUE,
    digest TEXT NOT NULL UNIQUE,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollments (
    peer_id TEXT NOT NULL,
    cnf TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    enrolled_at BIGINT NOT NULL,
    PRIMARY KEY (peer_id, cnf)
);
CREATE INDEX IF NOT EXISTS enrollments_peer_order
    ON enrollments (peer_id, enrolled_at);
"""


def _statements(sql: str) -> list[str]:
    out, buf = [], []
    for line in sql.splitlines():
        if line.strip().startswith("--"):
            continue
        buf.append(line)
        if line.rstrip().endswith(";"):
            stmt = "\n".join(buf).strip().rstrip(";").strip()
            if stmt:
                out.append(stmt)
            buf = []
    if buf and "".join(buf).strip():
        raise ValueError("schema statement missing semicolon")
    return out


async def migrate(dsn: str | None = None, schema: str = "capchain") -> None:
    """Create the schema. Run once from an init container, not from agents."""
    import psycopg

    dsn = dsn or os.environ["CAPCHAIN_POSTGRES_DSN"]
    schema = _ident("schema", schema)
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        await conn.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
        await conn.execute(f"SET search_path TO {schema}")
        for stmt in _statements(SCHEMA_SQL):
            await conn.execute(stmt)
        await conn.execute(
            "INSERT INTO evidence_head (id, head) VALUES (1, %s) ON CONFLICT (id) DO NOTHING",
            (_GENESIS,),
        )


# ---------------------------------------------------------------------------
# PostgreSQL implementations (psycopg_pool.AsyncConnectionPool)
# ---------------------------------------------------------------------------

class _Pg:
    def __init__(self, pool: object) -> None:
        self._pool = pool

    def _conn(self):
        return self._pool.connection()

    async def _timeout(self, cur: object) -> None:
        await cur.execute(
            "SELECT set_config('statement_timeout', %s, true)",
            (str(_STATEMENT_TIMEOUT_MS),),
        )

    async def ping(self) -> None:
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute("SELECT 1")


class PostgresReplayStore(_Pg):
    def __init__(self, pool: object, ttl_seconds: int) -> None:
        super().__init__(pool)
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._ttl = ttl_seconds

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    async def consume(self, key: tuple[str, ...], now: int) -> bool:
        encoded = _replay_key("nonce", key)
        del now
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute(
                """
                INSERT INTO replay_nonces (key, expires_at)
                VALUES (%s, (EXTRACT(EPOCH FROM NOW())::bigint + %s))
                ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at
                WHERE replay_nonces.expires_at <= EXTRACT(EPOCH FROM NOW())::bigint
                RETURNING key
                """,
                (encoded, self._ttl),
            )
            fresh = (await cur.fetchone()) is not None
            if (hash(encoded) & 0xFF) == 0:
                await cur.execute(
                    "DELETE FROM replay_nonces "
                    "WHERE expires_at <= EXTRACT(EPOCH FROM NOW())::bigint - 60"
                )
            return fresh

    async def prune(self, now: int) -> int:
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await cur.execute(
                "DELETE FROM replay_nonces WHERE expires_at <= %s",
                (now,),
            )
            return cur.rowcount


class PostgresBudgetLedger(_Pg):
    """Lock order is always chain, then hops sorted by jti, then the
    reservation. Same order in every method, so concurrent reserves of
    one cid cannot deadlock."""

    async def remaining(self, cid: str) -> int:
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                "SELECT remaining FROM budget_chains WHERE cid = %s",
                (cid,),
            )
            row = await cur.fetchone()
            return int(row[0]) if row else 0

    async def evict_expired(self, grace_seconds: int = 60) -> int:
        if grace_seconds < 0:
            raise ValueError("grace_seconds must be >= 0")
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute(
                """
                DELETE FROM budget_chains
                WHERE expires_at > 0
                AND expires_at < EXTRACT(EPOCH FROM NOW())::bigint - %s
                AND cid NOT IN (
                    SELECT DISTINCT cid FROM budget_reservations
                    WHERE state IN ('reserved', 'dispatched')
                )
                """,
                (grace_seconds,),
            )
            return cur.rowcount

    async def commit_abandoned(self, older_than_seconds: int) -> int:
        if older_than_seconds <= 0:
            raise ValueError("older_than_seconds must be > 0")
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                """SELECT handle, cid, amount, path_json
                FROM budget_reservations
                WHERE state = 'dispatched'
                    AND created_at < now() - make_interval(secs => %s)""",
                (older_than_seconds,),
            )
            rows = await cur.fetchall()
        n = 0
        for handle, cid, amount, path_json in rows:
            try:
                await self.settle(
                    SpendHandle(
                        cid=cid,
                        amount=int(amount),
                        handle=handle,
                        path=_load_path(path_json),
                    ),
                    int(amount),
                )
                n += 1
            except RejectError:
                pass
        return n

    async def reserve(
        self,
        cid: str,
        root_cap: int,
        path: tuple,
        amount: int,
        *,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> SpendHandle | None:
        if amount < 0 or root_cap < 0:
            raise ValueError("bad reserve args")
        ordered = _check_path(path)
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute(
                """INSERT INTO budget_chains (cid, root_cap, remaining, expires_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cid) DO UPDATE
                SET expires_at = GREATEST(
                    COALESCE(budget_chains.expires_at, 0),
                    COALESCE(EXCLUDED.expires_at, 0)
                )""",
                (cid, root_cap, root_cap, expires_at if expires_at is not None else 0),
            )
            await cur.execute(
                "SELECT root_cap, remaining FROM budget_chains "
                "WHERE cid = %s FOR UPDATE",
                (cid,),
            )
            db_root, db_rem = await cur.fetchone()
            if db_root != root_cap:
                raise RejectError(Code.BUDGET_CAP_CHANGED, f"cid {cid}")
            fits = db_rem >= amount
            for jti, cap in ordered:
                await cur.execute(
                    """INSERT INTO budget_hops (cid, jti, cap, spent)
                    VALUES (%s, %s, %s, 0) ON CONFLICT (cid, jti) DO NOTHING""",
                    (cid, jti, cap),
                )
                await cur.execute(
                    """SELECT cap, spent FROM budget_hops
                    WHERE cid = %s AND jti = %s FOR UPDATE""",
                    (cid, jti),
                )
                db_cap, db_spent = await cur.fetchone()
                if db_cap != cap:
                    raise RejectError(Code.BUDGET_CAP_CHANGED, f"jti {jti}")
                if db_spent + amount > db_cap:
                    fits = False
            if not fits:
                return None
            await cur.execute(
                "UPDATE budget_chains SET remaining = remaining - %s WHERE cid = %s",
                (amount, cid),
            )
            for jti, _ in ordered:
                await cur.execute(
                    """UPDATE budget_hops SET spent = spent + %s
                    WHERE cid = %s AND jti = %s""",
                    (amount, cid, jti),
                )
            handle = uuid.uuid4().hex
            await cur.execute(
                """INSERT INTO budget_reservations
                (handle, cid, amount, path_json, state)
                VALUES (%s, %s, %s, %s, 'reserved')""",
                (handle, cid, amount, _dump_path(ordered)),
            )
            return SpendHandle(cid=cid, amount=amount, handle=handle, path=ordered)

    async def mark_dispatched(self, handle: SpendHandle) -> None:
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute(
                "SELECT cid FROM budget_chains WHERE cid = %s FOR UPDATE",
                (handle.cid,),
            )
            await cur.execute(
                """UPDATE budget_reservations SET state = 'dispatched'
                WHERE handle = %s AND state = 'reserved'""",
                (handle.handle,),
            )
            if cur.rowcount != 1:
                raise RejectError(Code.INTERNAL, "dispatch: bad state")
        handle.state = ReservationState.DISPATCHED

    async def settle(self, handle: SpendHandle, actual: int) -> None:
        if type(actual) is not int or actual < 0:
            raise RejectError(Code.INTERNAL, "actual must be a non-negative int")
        ordered = _check_path(handle.path)
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute(
                "SELECT remaining FROM budget_chains WHERE cid = %s FOR UPDATE",
                (handle.cid,),
            )
            chain = await cur.fetchone()
            if chain is None:
                raise RejectError(Code.INTERNAL, "settle: chain lost")
            await cur.execute(
                """SELECT amount, state FROM budget_reservations
                   WHERE handle = %s FOR UPDATE""",
                (handle.handle,),
            )
            row = await cur.fetchone()
            if row is None:
                raise RejectError(Code.INTERNAL, "settle: handle lost")
            reserved, state = row
            if state != ReservationState.DISPATCHED:
                raise RejectError(Code.INTERNAL, f"settle from {state}")
            delta = actual - int(reserved)
            hops = []
            for jti, _ in ordered:
                await cur.execute(
                    """SELECT cap, spent FROM budget_hops
                       WHERE cid = %s AND jti = %s FOR UPDATE""",
                    (handle.cid, jti),
                )
                hops.append(await cur.fetchone())
            if delta != 0:
                if int(chain[0]) - delta < 0:
                    raise RejectError(Code.BUDGET_EXHAUSTED, "root on settle")
                for jti, (cap, spent) in zip(
                    (j for j, _ in ordered),
                    hops,
                    strict=False,
                ):
                    nxt = int(spent) + delta
                    if nxt < 0 or nxt > int(cap):
                        raise RejectError(
                            Code.BUDGET_EXHAUSTED,
                            f"hop {jti} on settle",
                        )
                await cur.execute(
                    "UPDATE budget_chains SET remaining = remaining - %s WHERE cid = %s",
                    (delta, handle.cid),
                )
                for jti, _ in ordered:
                    await cur.execute(
                        """UPDATE budget_hops SET spent = spent + %s
                           WHERE cid = %s AND jti = %s""",
                        (delta, handle.cid, jti),
                    )
            await cur.execute(
                """UPDATE budget_reservations SET amount = %s, state = 'settled'
                   WHERE handle = %s""",
                (actual, handle.handle),
            )
            handle.amount = actual
            handle.state = ReservationState.SETTLED

    async def commit(self, handle: SpendHandle) -> None:
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await cur.execute(
                "DELETE FROM budget_reservations WHERE handle = %s",
                (handle.handle,),
            )

    async def refund(self, handle: SpendHandle) -> None:
        ordered = _check_path(handle.path)
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute(
                "SELECT remaining FROM budget_chains WHERE cid = %s FOR UPDATE",
                (handle.cid,),
            )
            for jti, _ in ordered:
                await cur.execute(
                    """SELECT spent FROM budget_hops
                       WHERE cid = %s AND jti = %s FOR UPDATE""",
                    (handle.cid, jti),
                )
            await cur.execute(
                """DELETE FROM budget_reservations
                   WHERE handle = %s AND state = 'reserved' RETURNING amount""",
                (handle.handle,),
            )
            row = await cur.fetchone()
            if row is None:
                return
            handle.state = ReservationState.CANCELLED
            amount = int(row[0])
            await cur.execute(
                "UPDATE budget_chains SET remaining = remaining + %s WHERE cid = %s",
                (amount, handle.cid),
            )
            for jti, _ in ordered:
                await cur.execute(
                    """UPDATE budget_hops SET spent = GREATEST(0, spent - %s)
                       WHERE cid = %s AND jti = %s""",
                    (amount, handle.cid, jti),
                )

    async def refund_abandoned(self, older_than_seconds: int) -> int:
        if older_than_seconds <= 0:
            raise ValueError("older_than_seconds must be > 0")
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                """SELECT handle, cid, amount, path_json FROM budget_reservations
                   WHERE state = 'reserved'
                     AND created_at < now() - make_interval(secs => %s)""",
                (older_than_seconds,),
            )
            rows = await cur.fetchall()
        n = 0
        for handle, cid, amount, path_json in rows:
            await self.refund(
                SpendHandle(
                    cid=cid,
                    amount=int(amount),
                    handle=handle,
                    path=_load_path(path_json),
                )
            )
            n += 1
        return n


class PostgresRevocationStore(_Pg):
    async def _add(self, kind: str, value: str) -> None:
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await cur.execute(
                """INSERT INTO revocations (kind, value) VALUES (%s, %s)
                   ON CONFLICT DO NOTHING""",
                (kind, value),
            )

    async def revoke_agent(self, value: str) -> None:
        await self._add("agent", value)

    async def revoke_key(self, value: str) -> None:
        await self._add("kid", value)

    async def revoke_chain(self, value: str) -> None:
        await self._add("cid", value)

    async def revoke_token(self, value: str) -> None:
        await self._add("jti", value)

    async def find_revoked(
        self,
        *,
        agents: tuple[str, ...] = (),
        kids: tuple[str, ...] = (),
        cids: tuple[str, ...] = (),
        jtis: tuple[str, ...] = (),
    ) -> tuple[str, str] | None:
        groups = (
            ("agent", agents),
            ("kid", kids),
            ("cid", cids),
            ("jti", jtis),
        )
        if not any(items for _, items in groups):
            return None
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                """
                SELECT kind, value FROM revocations
                WHERE (kind = 'agent' AND value = ANY(%s))
                   OR (kind = 'kid' AND value = ANY(%s))
                   OR (kind = 'cid' AND value = ANY(%s))
                   OR (kind = 'jti' AND value = ANY(%s))
                """,
                (
                    list(agents),
                    list(kids),
                    list(cids),
                    list(jtis),
                ),
            )
            found = {(kind, value) for kind, value in await cur.fetchall()}
        for kind, items in groups:
            for item in items:
                if (kind, item) in found:
                    return (kind, item)
        return None


class PostgresEvidenceLog(_Pg):
    async def append(self, draft: dict) -> Evidence:
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute("SELECT head FROM evidence_head WHERE id = 1 FOR UPDATE")
            row = await cur.fetchone()
            if row is None:
                raise RejectError(Code.STATE_UNAVAILABLE, "evidence head missing")
            ev = _evidence(draft, row[0])
            await cur.execute(
                """INSERT INTO evidence (prev_hash, digest, body)
                   VALUES (%s, %s, %s)""",
                (ev.prev_hash, ev.digest(), _dump_evidence(ev)),
            )
            await cur.execute(
                "UPDATE evidence_head SET head = %s WHERE id = 1",
                (ev.digest(),),
            )
            return ev

    async def verify_integrity(self) -> bool:
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute("SELECT head FROM evidence_head WHERE id = 1")
            head = await cur.fetchone()
            await cur.execute("SELECT body, digest FROM evidence ORDER BY seq")
            rows = await cur.fetchall()
        prev = _GENESIS
        for body, digest in rows:
            ev = _load_evidence(body)
            if ev.prev_hash != prev or ev.digest() != digest:
                return False
            prev = digest
        return head is not None and prev == head[0]

    async def records(self) -> tuple[Evidence, ...]:
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute("SELECT body FROM evidence ORDER BY seq")
            return tuple(_load_evidence(row[0]) for row in await cur.fetchall())


class PostgresEnrollments(_Pg):
    def __init__(
        self,
        pool: object,
        ttl_seconds: int,
        max_per_peer: int,
    ) -> None:
        super().__init__(pool)
        if ttl_seconds <= 0 or max_per_peer <= 0:
            raise ValueError("ttl_seconds and max_per_peer must be > 0")
        self._ttl = ttl_seconds
        self._max = max_per_peer

    async def add(self, peer_id: str, cnf: str, now: int) -> None:
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            await self._timeout(cur)
            await cur.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (peer_id,),
            )
            await cur.execute(
                "DELETE FROM enrollments "
                "WHERE peer_id = %s AND expires_at <= %s",
                (peer_id, now),
            )
            await cur.execute(
                """INSERT INTO enrollments (peer_id, cnf, expires_at, enrolled_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (peer_id, cnf) DO UPDATE
                SET expires_at = EXCLUDED.expires_at,
                    enrolled_at = EXCLUDED.enrolled_at""",
                (peer_id, cnf, now + self._ttl, now),
            )
            await cur.execute(
                """DELETE FROM enrollments WHERE peer_id = %s AND cnf NOT IN (
                    SELECT cnf FROM enrollments WHERE peer_id = %s
                    ORDER BY enrolled_at DESC LIMIT %s)""",
                (peer_id, peer_id, self._max),
            )

    async def require(self, peer_id: str, cnf: str, now: int) -> None:
        async with (
            self._conn() as conn,
            conn.cursor() as cur,
        ):
            await cur.execute(
                """SELECT expires_at FROM enrollments
                   WHERE peer_id = %s AND cnf = %s""",
                (peer_id, cnf),
            )
            row = await cur.fetchone()
        if row is None or int(row[0]) <= now:
            raise RejectError(
                Code.NOT_ENROLLED,
                "key not enrolled for this SPIFFE ID",
            )

    async def revoke(self, peer_id: str, cnf: str | None = None) -> None:
        async with (
            self._conn() as conn,
            conn.transaction(),
            conn.cursor() as cur,
        ):
            if cnf is None:
                await cur.execute(
                    "DELETE FROM enrollments WHERE peer_id = %s",
                    (peer_id,),
                )
            else:
                await cur.execute(
                    "DELETE FROM enrollments WHERE peer_id = %s AND cnf = %s",
                    (peer_id, cnf),
                )


# ---------------------------------------------------------------------------
# Client pool (async)
# ---------------------------------------------------------------------------

class _AsyncClients:
    def __init__(self) -> None:
        self._redis: dict[str, object] = {}
        self.pg: dict[str, object] = {}
        self._redis_urls: list[str] = []

    async def redis(self, url: str | None, prefix: str) -> tuple[object, str]:
        if not url:
            raise ValueError(
                "redis store requires redis_url / CAPCHAIN_REDIS_URL"
            )
        client = self._redis.get(url)
        if client is None:
            try:
                from redis import asyncio as aioredis
            except ImportError as e:
                raise RuntimeError("pip install 'redis>=5'") from e
            client = aioredis.Redis.from_url(
                url,
                decode_responses=True,
                socket_timeout=_SOCKET_TIMEOUT,
                health_check_interval=30,
            )
            self._redis[url] = client
            self._redis_urls.append(url)
        return client, prefix

    async def pool(self, dsn: str | None, schema: str) -> object:
        if not dsn:
            raise ValueError(
                "database store requires postgres_dsn / CAPCHAIN_POSTGRES_DSN"
            )
        key = dsn + "\0" + schema
        pool = self.pg.get(key)
        if pool is None:
            try:
                from psycopg_pool import AsyncConnectionPool
            except ImportError as e:
                raise RuntimeError(
                    "pip install 'psycopg[binary]>=3.1' 'psycopg-pool>=3.2'"
                ) from e
            pool = AsyncConnectionPool(
                dsn,
                min_size=1,
                max_size=8,
                timeout=_SOCKET_TIMEOUT,
                kwargs={
                    "autocommit": False,
                    "options": f"-c search_path={schema}",
                },
                open=False,
            )
            await pool.open()
            self.pg[key] = pool
        return pool

    async def close(self) -> None:
        for client in self._redis.values():
            await client.aclose()
        for pool in self.pg.values():
            await pool.close()
        self._redis.clear()
        self.pg.clear()


async def _open_replay(spec: StoreSpec, clients: _AsyncClients) -> object:
    ttl = spec.ttl_seconds or 300
    if spec.type == "memory":
        return InMemoryReplayStore(ttl_seconds=ttl)
    if spec.type == "redis":
        client, prefix = await clients.redis(spec.redis_url, spec.prefix)
        return RedisReplayStore(client, ttl_seconds=ttl, prefix=prefix)
    return PostgresReplayStore(
        await clients.pool(spec.postgres_dsn, spec.schema),
        ttl_seconds=ttl,
    )


async def _open_ledger(spec: StoreSpec, clients: _AsyncClients) -> object:
    if spec.type == "memory":
        return InMemoryBudgetLedger()
    if spec.type == "redis":
        client, prefix = await clients.redis(spec.redis_url, spec.prefix)
        return RedisBudgetLedger(client, prefix=prefix)
    return PostgresBudgetLedger(
        await clients.pool(spec.postgres_dsn, spec.schema)
    )


async def _open_revocation(spec: StoreSpec, clients: _AsyncClients) -> object:
    if spec.type == "memory":
        return InMemoryRevocationStore()
    if spec.type == "redis":
        client, prefix = await clients.redis(spec.redis_url, spec.prefix)
        return RedisRevocationStore(client, prefix=prefix)
    return PostgresRevocationStore(
        await clients.pool(spec.postgres_dsn, spec.schema)
    )


async def _open_evidence(spec: StoreSpec, clients: _AsyncClients) -> object:
    if spec.type == "memory":
        return InMemoryEvidenceLog()
    if spec.type == "redis":
        client, prefix = await clients.redis(spec.redis_url, spec.prefix)
        return RedisEvidenceLog(client, prefix=prefix)
    return PostgresEvidenceLog(
        await clients.pool(spec.postgres_dsn, spec.schema)
    )


async def _open_enrollments(spec: StoreSpec, clients: _AsyncClients) -> object:
    ttl = spec.ttl_seconds or 3600
    if spec.type == "memory":
        return InMemoryEnrollments(ttl_seconds=ttl)
    if spec.type == "redis":
        client, prefix = await clients.redis(spec.redis_url, spec.prefix)
        return RedisEnrollments(
            client,
            ttl_seconds=ttl,
            max_per_peer=spec.max_per_peer,
            prefix=prefix,
        )
    return PostgresEnrollments(
        await clients.pool(spec.postgres_dsn, spec.schema),
        ttl_seconds=ttl,
        max_per_peer=spec.max_per_peer,
    )


# ---------------------------------------------------------------------------
# Helpers (unchanged)
# ---------------------------------------------------------------------------

def _dump_path(path: tuple) -> str:
    return json.dumps(
        [[j, c] for j, c in path],
        separators=(",", ":"),
    )


def _load_path(raw: str) -> tuple:
    return tuple((j, int(c)) for j, c in json.loads(raw))


def _check_path(path: tuple) -> tuple:
    if not path:
        raise ValueError("empty budget path")
    jtis = [j for j, _ in path]
    if len(jtis) != len(set(jtis)):
        raise ValueError("duplicate jti in budget path")
    return tuple(sorted(path, key=lambda item: item[0]))


def _evidence(draft: dict, prev_hash: str) -> Evidence:
    fields = {k: v for k, v in draft.items() if k != "prev_hash"}
    jtis = fields.get("jtis", ())
    if not isinstance(jtis, tuple):
        fields["jtis"] = tuple(jtis)
    return Evidence(prev_hash=prev_hash, **fields)


def _dump_evidence(ev: Evidence) -> str:
    return json.dumps(
        {
            "action_id": ev.action_id,
            "code": ev.code,
            "cid": ev.cid,
            "jtis": list(ev.jtis),
            "peer_id": ev.peer_id,
            "issuer": ev.issuer,
            "holder": ev.holder,
            "action": ev.action,
            "resource": ev.resource,
            "payload_hash": ev.payload_hash,
            "cost_micros": ev.cost_micros,
            "ts": ev.ts,
            "pop_thumbprint": ev.pop_thumbprint,
            "channel_bound": ev.channel_bound,
            "prev_hash": ev.prev_hash,
            "verifier": ev.verifier,
            "related_id": ev.related_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_evidence(raw: str) -> Evidence:
    d = json.loads(raw)
    d["jtis"] = tuple(d["jtis"])
    return Evidence(**d)


async def _check_redis(
    clients: _AsyncClients,
    env: str,
    specs: tuple,
) -> None:
    """Verify Redis policy for every client. AOF is required in production
    if any durable store is backed by Redis (ledger, revocation, evidence,
    enrollments). Replay-only deployments may skip AOF."""
    uses_redis_for_durable = any(
        spec.type == "redis"
        and name in ("ledger", "revocation", "evidence", "enrollments")
        for name, spec in specs
    )
    for client in clients._redis.values():
        try:
            cfg = await client.config_get("maxmemory-policy") or {}
            policy = cfg.get("maxmemory-policy", "noeviction")
        except Exception as e:
            if env == "production":
                raise RuntimeError(
                    "cannot verify Redis maxmemory-policy"
                ) from e
            _log.warning(
                "capchain: Redis policy check skipped: %s",
                type(e).__name__,
            )
            continue
        if policy != "noeviction":
            msg = (
                f"Redis maxmemory-policy is {policy!r}; capchain requires "
                f"noeviction (evicting a nonce or a revocation fails open)"
            )
            if env == "production":
                raise RuntimeError(msg)
            _log.warning("capchain: %s", msg)
        if env == "production" and uses_redis_for_durable:
            try:
                info = await client.info("persistence")
            except Exception as e:
                raise RuntimeError(
                    "cannot verify Redis AOF state"
                ) from e
            if not info.get("aof_enabled"):
                raise RuntimeError(
                    "Redis AOF is off; capchain requires AOF in production "
                    "for ledger/revocation/evidence/enrollments"
                )


# ---------------------------------------------------------------------------
# Stores container (async)
# ---------------------------------------------------------------------------

@dataclass
class Stores:
    replay: ReplayStore
    ledger: BudgetLedger
    revocation: RevocationStore
    evidence: EvidenceStore
    enrollments: EnrollmentStore
    env: str
    _close: Callable[[], Awaitable[None]]

    @classmethod
    async def open(
        cls,
        type: str = "memory",
        *,
        redis_url: str | None = None,
        postgres_dsn: str | None = None,
        replay: str | None = None,
        ledger: str | None = None,
        revocation: str | None = None,
        evidence: str | None = None,
        enrollments: str | None = None,
        env: str | None = None,
        prefix: str = "capchain",
        schema: str = "capchain",
        replay_ttl: int = 300,
        enroll_ttl: int = 3600,
        enroll_max_per_peer: int = 8,
    ) -> Stores:
        def spec(override: str | None, ttl: int | None) -> StoreSpec:
            return StoreSpec(
                type=_kind(override or type),
                redis_url=redis_url,
                postgres_dsn=postgres_dsn,
                prefix=prefix,
                schema=_ident("schema", schema),
                ttl_seconds=ttl,
                max_per_peer=enroll_max_per_peer,
            )

        return await cls._build(
            replay=spec(replay, replay_ttl),
            ledger=spec(ledger, None),
            revocation=spec(revocation, None),
            evidence=spec(evidence, None),
            enrollments=spec(enrollments, enroll_ttl),
            env=env or os.environ.get("CAPCHAIN_ENV", "development"),
        )

    @classmethod
    async def _build(
        cls,
        *,
        replay: StoreSpec,
        ledger: StoreSpec,
        revocation: StoreSpec,
        evidence: StoreSpec,
        enrollments: StoreSpec,
        env: str,
    ) -> Stores:
        specs = (
            ("replay", replay),
            ("ledger", ledger),
            ("revocation", revocation),
            ("evidence", evidence),
            ("enrollments", enrollments),
        )
        if env == "production":
            for name, spec in specs:
                if spec.type == "memory":
                    raise RuntimeError(
                        f"{name}: memory is process-local and is refused "
                        f"when CAPCHAIN_ENV=production"
                    )
        clients = _AsyncClients()
        try:
            replay_store = await _open_replay(replay, clients)
            ledger_store = await _open_ledger(ledger, clients)
            revocation_store = await _open_revocation(revocation, clients)
            evidence_store = await _open_evidence(evidence, clients)
            enrollments_store = await _open_enrollments(enrollments, clients)
            built = cls(
                replay=replay_store,
                ledger=ledger_store,
                revocation=revocation_store,
                evidence=evidence_store,
                enrollments=enrollments_store,
                env=env,
                _close=clients.close,
            )
            await built.ping()
            await _check_redis(clients, env, specs)
        except BaseException:
            await clients.close()
            raise
        _log.info(
            "capchain stores env=%s replay=%s ledger=%s revocation=%s evidence=%s enrollments=%s",
            env,
            replay.type,
            ledger.type,
            revocation.type,
            evidence.type,
            enrollments.type,
        )
        if ledger.type == "redis":
            _log.warning(
                "capchain: Redis ledger survives only its AOF window; "
                "prefer database for the ledger"
            )
        if evidence.type == "redis":
            _log.warning(
                "capchain: Redis evidence is not an insert-only log; "
                "prefer database for evidence"
            )
        return built

    @classmethod
    async def from_env(cls) -> Stores:
        default = os.environ.get("CAPCHAIN_STORE", "memory")
        redis_url = os.environ.get("CAPCHAIN_REDIS_URL")
        dsn = os.environ.get("CAPCHAIN_POSTGRES_DSN")
        prefix = os.environ.get("CAPCHAIN_REDIS_PREFIX", "capchain")
        schema = os.environ.get("CAPCHAIN_POSTGRES_SCHEMA", "capchain")
        try:
            max_per_peer = int(
                os.environ.get("CAPCHAIN_ENROLL_MAX_PER_PEER", "8")
            )
        except ValueError as e:
            raise RuntimeError(
                f"CAPCHAIN_ENROLL_MAX_PER_PEER: {e}"
            ) from None

        def one(
            name: str,
            ttl_env: str,
            default_ttl: int | None,
        ) -> StoreSpec:
            raw_ttl = os.environ.get(ttl_env)
            try:
                ttl = int(raw_ttl) if raw_ttl is not None else default_ttl
            except ValueError as e:
                raise RuntimeError(f"{ttl_env}: {e}") from None

            return StoreSpec(
                type=_kind(
                    os.environ.get(
                        f"CAPCHAIN_STORE_{name}",
                        default,
                    )
                ),
                redis_url=os.environ.get(
                    f"CAPCHAIN_{name}_REDIS_URL",
                    redis_url,
                ),
                postgres_dsn=os.environ.get(
                    f"CAPCHAIN_{name}_POSTGRES_DSN",
                    dsn,
                ),
                prefix=prefix,
                schema=_ident("schema", schema),
                ttl_seconds=ttl,
                max_per_peer=max_per_peer,
            )

        return await cls._build(
            replay=one("REPLAY", "CAPCHAIN_REPLAY_TTL", 300),
            ledger=one("LEDGER", "CAPCHAIN_LEDGER_TTL", None),
            revocation=one("REVOCATION", "CAPCHAIN_REVOCATION_TTL", None),
            evidence=one("EVIDENCE", "CAPCHAIN_EVIDENCE_TTL", None),
            enrollments=one("ENROLLMENTS", "CAPCHAIN_ENROLL_TTL", 3600),
            env=os.environ.get("CAPCHAIN_ENV", "development"),
        )

    def as_gateway_kwargs(self) -> dict:
        return {
            "ledger": self.ledger,
            "replay": self.replay,
            "revocation": self.revocation,
            "evidence": self.evidence,
        }

    def as_issuer_kwargs(self) -> dict:
        return {"enrollments": self.enrollments}

    async def ping(self) -> None:
        for store in (
            self.replay,
            self.ledger,
            self.revocation,
            self.evidence,
            self.enrollments,
        ):
            ping = getattr(store, "ping", None)
            if ping is not None:
                await ping()

    async def close(self) -> None:
        await self._close()

    async def __aenter__(self) -> Stores:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# Contract test and selftest (async)
# ---------------------------------------------------------------------------

def _draft(action_id: str = "a1") -> dict:
    return {
        "action_id": action_id,
        "code": Code.OK,
        "cid": "c",
        "jtis": ("j",),
        "peer_id": "spiffe://t/a",
        "issuer": "spiffe://t/m",
        "holder": "spiffe://t/a",
        "action": "infer",
        "resource": "llm",
        "payload_hash": "sha256:" + "ab" * 32,
        "cost_micros": 1,
        "ts": 1,
        "pop_thumbprint": "",
        "channel_bound": False,
        "verifier": "spiffe://t/g",
        "related_id": "",
    }


async def check_contract(stores: Stores) -> None:
    now = _now()
    assert await stores.replay.consume(("pop", "n1"), now) is True
    assert await stores.replay.consume(("pop", "n1"), now) is False

    path = (("j1", 500), ("j0", 1000))
    first = await stores.ledger.reserve("cid-1", 1000, path, 100)
    assert first is not None and await stores.ledger.remaining("cid-1") == 900
    await stores.ledger.refund(first)
    assert await stores.ledger.remaining("cid-1") == 1000
    second = await stores.ledger.reserve("cid-1", 1000, path, 100)
    await stores.ledger.mark_dispatched(second)
    await stores.ledger.refund(second)  # dispatched: not refundable
    assert await stores.ledger.remaining("cid-1") == 900
    await stores.ledger.settle(second, 80)
    assert await stores.ledger.remaining("cid-1") == 920
    await stores.ledger.commit(second)
    try:
        await stores.ledger.reserve("cid-1", 999, path, 1)
        raise AssertionError("cap change was accepted")
    except RejectError as e:
        assert e.code == Code.BUDGET_CAP_CHANGED

    await stores.revocation.revoke_key("abc")
    assert await stores.revocation.find_revoked(kids=("abc",)) == ("kid", "abc")
    assert await stores.revocation.find_revoked(kids=("nope",)) is None

    await stores.evidence.append(_draft("a1"))
    await stores.evidence.append(_draft("a2"))
    assert await stores.evidence.verify_integrity()
    assert len(await stores.evidence.records()) >= 2

    await stores.enrollments.add("spiffe://t/a", "k-old", now)
    await stores.enrollments.add("spiffe://t/a", "k-new", now)
    await stores.enrollments.require("spiffe://t/a", "k-new", now)
    try:
        await stores.enrollments.require("spiffe://t/a", "missing", now)
        raise AssertionError("missing enrollment was accepted")
    except RejectError as e:
        assert e.code == Code.NOT_ENROLLED


async def selftest() -> int:
    failures = 0
    async with await Stores.open("memory") as stores:
        try:
            await check_contract(stores)
            print("  [ok]   memory")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] memory: {type(e).__name__}: {e}")
    url = os.environ.get("CAPCHAIN_TEST_REDIS")
    if url:
        prefix = f"capchain:test:{uuid.uuid4().hex}"
        try:
            async with await Stores.open(
                "redis",
                redis_url=url,
                prefix=prefix,
                env="development",
            ) as stores:
                await check_contract(stores)
            print("  [ok]   redis")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] redis: {type(e).__name__}: {e}")
    dsn = os.environ.get("CAPCHAIN_TEST_POSTGRES")
    if dsn:
        schema = "capchain_test_" + uuid.uuid4().hex[:12]
        try:
            await migrate(dsn, schema)
            async with await Stores.open(
                "database",
                postgres_dsn=dsn,
                schema=schema,
                env="development",
            ) as stores:
                await check_contract(stores)
            print("  [ok]   database")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] database: {type(e).__name__}: {e}")
    print(f"store selftest: {failures} failure(s)")
    return failures


if __name__ == "__main__":
    raise SystemExit(asyncio.run(selftest()))