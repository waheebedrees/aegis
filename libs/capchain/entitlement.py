from __future__ import annotations

import hashlib
import threading
from collections.abc import Mapping
from dataclasses import dataclass

import libs.capchain as cc

# Verify these against the actual cc.Token leaf schema.
CLAIM_ISSUER = "iss"
CLAIM_HOLDER = "holder"
CLAIM_CNF = "cnf"
# CLAIM_ISSUED_AT = "iat"
CLAIM_ISSUED_AT = "nbf"
CLAIM_EXPIRES_AT = "exp"
CLAIM_JTI = "jti"
CLAIM_SCOPE = "scope"

MAX_JTI_LENGTH = 256
MAX_CLAIM_LENGTH = 1024


class EntitlementError(Exception):
    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _string(m: Mapping, key: str) -> str:
    value = m.get(key)

    if not isinstance(value, str) or not value:
        raise EntitlementError("BAD_TOKEN", f"field {key}")

    if len(value) > MAX_CLAIM_LENGTH:
        raise EntitlementError("BAD_TOKEN", f"field {key} too long")

    return value


def _integer(m: Mapping, key: str) -> int:
    value = m.get(key)

    if isinstance(value, bool) or not isinstance(value, int):
        raise EntitlementError("BAD_TOKEN", f"field {key}")

    return value


def _string_set(m: Mapping, key: str) -> frozenset[str]:
    value = m.get(key)

    if not isinstance(value, (list, tuple)):
        raise EntitlementError("BAD_TOKEN", f"field {key}")

    if not value:
        raise EntitlementError("BAD_TOKEN", f"empty {key}")

    if not all(
        isinstance(item, str) and bool(item.strip()) and len(item) <= MAX_CLAIM_LENGTH
        for item in value
    ):
        raise EntitlementError("BAD_TOKEN", f"invalid {key}")

    return frozenset(value)


def _allows(allowed: frozenset[str], requested: frozenset[str]) -> bool:
    """Explicit wildcard semantics; no implicit wildcard expansion."""
    return bool(requested) and ("*" in allowed or requested.issubset(allowed))


def _decode_leaf(token: bytes) -> tuple[Mapping, int]:
    try:
        decoded = cc.Token.decode(token)
        blocks = decoded.blocks

        if not blocks:
            raise ValueError("empty token chain")

        leaf = blocks[-1].body()

        if not isinstance(leaf, Mapping):
            raise ValueError("invalid leaf")

        return leaf, len(blocks)

    except Exception:
        raise EntitlementError("BAD_TOKEN", "undecodable") from None


@dataclass(frozen=True, slots=True)
class Entitlement:
    """Independent operator-controlled authorization policy."""

    cnf: frozenset[str]
    tools: frozenset[str]
    audience: frozenset[str]

    max_budget_micros: int
    max_ttl_seconds: int

    max_outstanding_budget_micros: int
    max_live_tokens: int

    def __post_init__(self) -> None:
        for name in ("cnf", "tools", "audience"):
            values = getattr(self, name)

            if not isinstance(values, frozenset) or not values:
                raise ValueError(f"{name} must be a non-empty frozenset")

            if not all(
                isinstance(v, str) and bool(v.strip()) and len(v) <= MAX_CLAIM_LENGTH
                for v in values
            ):
                raise ValueError(f"invalid {name}")

        limits = (
            self.max_budget_micros,
            self.max_ttl_seconds,
            self.max_outstanding_budget_micros,
            self.max_live_tokens,
        )

        if any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in limits):
            raise ValueError("all limits must be positive integers")

        if self.max_outstanding_budget_micros < self.max_budget_micros:
            raise ValueError("outstanding cap < per-token cap")


@dataclass(frozen=True, slots=True)
class Checked:
    key: tuple[str, str]
    digest: str
    jti: str
    budget: int
    exp: int
    row: Entitlement


def _decode_chain(token: bytes) -> tuple[Mapping, Mapping]:
    """Return (root_body, leaf_body).

    Depth is enforced by verify_chain via Policy.max_depth, not here.
    For a 1-block token root == leaf.
    """
    try:
        decoded = cc.Token.decode(token)
        blocks = decoded.blocks
        if not blocks:
            raise ValueError("empty token chain")
        root = blocks[0].body()
        leaf = blocks[-1].body()
        if not isinstance(root, Mapping) or not isinstance(leaf, Mapping):
            raise ValueError("invalid body")
        return root, leaf
    except Exception:
        raise EntitlementError("BAD_TOKEN", "undecodable") from None


class EntitlementTable:
    """
    Broker-side independent entitlement enforcement.

    check():
        Stateless validation. Does not authenticate the token signature.

    admit():
        Stateful accounting. Must only be called after gateway
        authentication and authorization have succeeded.

    This implementation is thread-safe within one process.
    Multi-process deployments require shared transactional storage.
    """

    def __init__(
        self,
        rows: Mapping[tuple[str, str], Entitlement],
    ) -> None:
        self._rows = dict(rows)

        if not self._rows:
            raise ValueError("at least one entitlement is required")

        for key, row in self._rows.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or not all(isinstance(v, str) and v for v in key)
            ):
                raise ValueError("invalid entitlement key")

            if not isinstance(row, Entitlement):
                raise TypeError("invalid entitlement row")

        # (issuer, holder) -> digest -> (exp, budget)
        self._live: dict[
            tuple[str, str],
            dict[str, tuple[int, int]],
        ] = {}

        # JTI uniqueness is scoped to issuer.
        # (issuer, jti) -> (digest, exp)
        self._jti: dict[
            tuple[str, str],
            tuple[str, int],
        ] = {}

        self._next_sweep = 0

        # Protects admission, JTI registration and expiration cleanup.
        self._lock = threading.RLock()

    # ---------------------------------------------------------
    # Stateless validation
    # ---------------------------------------------------------

    def check(
        self,
        token: bytes,
        *,
        peer_id: str,
        now: int,
    ) -> Checked:
        """
        Validate entitlement claims against the authenticated TLS peer.

        This method deliberately does not mutate accounting state.
        The gateway must subsequently authenticate the signature and PoP.
        """

        if not isinstance(token, bytes) or not token:
            raise EntitlementError("BAD_TOKEN", "empty token")

        if isinstance(now, bool) or not isinstance(now, int):
            raise ValueError("now must be an integer timestamp")

        if not isinstance(peer_id, str) or not peer_id:
            raise ValueError("invalid peer_id")

        root, leaf = _decode_chain(token)

        # Depth is checked by verify_chain (Policy.max_depth). Duplicating
        # it here couples two independent decisions.
        issuer_root = _string(root, CLAIM_ISSUER)
        holder = _string(leaf, CLAIM_HOLDER)
        cnf = _string(leaf, CLAIM_CNF)
        jti = _string(leaf, CLAIM_JTI)

        if len(jti) > MAX_JTI_LENGTH:
            raise EntitlementError("BAD_TOKEN", "jti too long")

        if holder != peer_id:
            raise EntitlementError("WRONG_HOLDER", peer_id)

        # Entitlement key: (root_issuer, leaf_holder).
        #   * 1-block token: root == leaf, so this is (leaf.iss, leaf.holder)
        #     — identical to the old behaviour. Existing tests are unaffected.
        #   * N-block token: still resolves to the root issuer, so every
        #     delegation from one root draws from one row. That is what makes
        #     max_outstanding_budget_micros bound *total* delegation rather
        #     than per-hop spend.
        row = self._rows.get((issuer_root, holder))
        if row is None:
            raise EntitlementError("NO_ENTITLEMENT", f"{issuer_root} -> {holder}")

        if cnf not in row.cnf:
            raise EntitlementError("CNF_NOT_REGISTERED", holder)

        scope = leaf.get(CLAIM_SCOPE)
        if not isinstance(scope, Mapping):
            raise EntitlementError("BAD_TOKEN", "scope")

        tools = _string_set(scope, "tools")
        audience = _string_set(scope, "audience")

        if not _allows(row.tools, tools):
            raise EntitlementError(
                "SCOPE_EXCEEDS_ENTITLEMENT",
                ",".join(sorted(tools - row.tools))[:128],
            )

        if not _allows(row.audience, audience):
            raise EntitlementError("AUDIENCE_EXCEEDS_ENTITLEMENT")

        budget = _integer(scope, "budget")
        if not 0 <= budget <= row.max_budget_micros:
            raise EntitlementError("BUDGET_EXCEEDS_ENTITLEMENT", str(budget))

        issued_at = _integer(leaf, CLAIM_ISSUED_AT)
        exp = _integer(leaf, CLAIM_EXPIRES_AT)

        if issued_at > now:
            raise EntitlementError("TOKEN_NOT_YET_VALID")
        if exp <= issued_at:
            raise EntitlementError("BAD_TOKEN", "invalid token lifetime")
        if exp <= now:
            raise EntitlementError("TOKEN_EXPIRED")
        if exp - issued_at > row.max_ttl_seconds:
            raise EntitlementError("TTL_EXCEEDS_ENTITLEMENT", str(exp - issued_at))

        return Checked(
            key=(issuer_root, holder),
            digest=hashlib.sha256(token).hexdigest(),
            jti=jti,
            budget=budget,
            exp=exp,
            row=row,
        )

    # ---------------------------------------------------------
    # Stateful admission
    # ---------------------------------------------------------

    def admit(self, checked: Checked, *, now: int) -> None:
        """
        Atomically register an authenticated capability.

        Identical token admission is idempotent.
        Different token bytes with the same issuer/JTI are rejected.

        Call only after gateway authorization succeeds.
        """

        if isinstance(now, bool) or not isinstance(now, int):
            raise ValueError("now must be an integer timestamp")

        if checked.exp <= now:
            raise EntitlementError("TOKEN_EXPIRED")

        with self._lock:
            self._sweep(now)

            issuer, holder = checked.key

            # Never trust a Checked object whose policy row does not match
            # the table's current registered policy.
            current_row = self._rows.get(checked.key)

            if current_row is None or current_row != checked.row:
                raise EntitlementError("NO_ENTITLEMENT")

            if checked.budget < 0 or checked.budget > current_row.max_budget_micros:
                raise EntitlementError("BUDGET_EXCEEDS_ENTITLEMENT")

            live = self._live.setdefault(checked.key, {})

            # JTI is unique per issuer, not per holder.
            jti_key = (issuer, checked.jti)
            prior = self._jti.get(jti_key)

            if prior is not None and prior[1] > now and prior[0] != checked.digest:
                raise EntitlementError(
                    "JTI_CONFLICT",
                    checked.jti[:32],
                )

            # Idempotent admission of the same token.
            if checked.digest in live:
                return

            if len(live) >= current_row.max_live_tokens:
                raise EntitlementError(
                    "TOO_MANY_LIVE_TOKENS",
                    str(len(live)),
                )

            outstanding = sum(budget for _, budget in live.values())

            if outstanding + checked.budget > current_row.max_outstanding_budget_micros:
                raise EntitlementError(
                    "OUTSTANDING_BUDGET_EXCEEDED",
                    f"{outstanding}+{checked.budget}",
                )

            # Commit both indexes while holding the same lock.
            live[checked.digest] = (
                checked.exp,
                checked.budget,
            )

            self._jti[jti_key] = (
                checked.digest,
                checked.exp,
            )

    # ---------------------------------------------------------
    # Expiration cleanup
    # ---------------------------------------------------------

    def _sweep(self, now: int) -> None:
        """Must be called with _lock held."""

        if now < self._next_sweep:
            return

        self._next_sweep = now + 60

        for jti_key, (_, exp) in list(self._jti.items()):
            if exp <= now:
                del self._jti[jti_key]

        for key, live in list(self._live.items()):
            for digest, (exp, _) in list(live.items()):
                if exp <= now:
                    del live[digest]

            if not live:
                del self._live[key]

    def check_and_admit(
        self,
        token: bytes,
        *,
        peer_id: str,
        now: int,
        authenticated: bool,
    ) -> Checked:
        if authenticated is not True:
            raise EntitlementError("UNAUTHENTICATED")

        checked = self.check(
            token,
            peer_id=peer_id,
            now=now,
        )

        self.admit(checked, now=now)
        return checked
