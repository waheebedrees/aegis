

from __future__ import annotations
import logging
from typing import Optional, Any
from dataclasses import dataclass

from contextlib import contextmanager
from collections.abc import Iterable
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from collections.abc import Iterable, Mapping
import hmac

import json
import hashlib
import base64
from enum import StrEnum
log = logging.getLogger(__name__)

ENROLLMENT_CTX = b"capchain/enrollment-receipt-v1\x00"
ENROLLMENT_RECEIPT_FIELDS = frozenset({"ver", "typ", "holder", "cnf", "nbf", "exp"})
MAX_RECEIPT_TTL_SECONDS = 86400 * 7   # one week; tune to your rotation cadence

# Wire version and derived labels

WIRE_VERSION: int = 2
"""Mandatory first field of every signed payload. A verifier that does
not understand a version MUST raise VERSION_UNSUPPORTED, never attempt
to interpret the rest."""

WIRE: str = f"v{WIRE_VERSION}"
"""Label component derived from WIRE_VERSION. Every domain string below
is built from it."""

CTX_BLOCK: bytes = f"capchain/{WIRE}/block".encode("ascii")
CTX_POP: bytes = f"capchain/{WIRE}/pop".encode("ascii")
CTX_ENROLL: bytes = f"capchain/{WIRE}/enroll".encode("ascii")
LINK_LABEL: bytes = f"capchain/{WIRE}/block-link".encode("ascii")


BudgetPath = tuple[tuple[str, int], ...]
"""((jti, cap), ...) from root to leaf."""

# Sentinels

ANY: str = "*"
"""The only wildcard in Scope. An empty frozenset means NOTHING, never
everything. Using emptiness as 'unrestricted' is a silent attenuation
bypass on the parent side of is_subset_of."""

GENESIS_PREV_HASH: str = "0" * 64
"""Sentinel for Block.prev on block 0. Not a hash of anything; chosen
so it cannot collide with a real link hash (sha256 hex of a non-empty
byte string)."""

GENESIS_LINK: str = GENESIS_PREV_HASH
"""Alias used by _wire and _chain."""

GENESIS_HASH: str = GENESIS_PREV_HASH
"""Alias used by _evidence for the first prev_hash."""

HEX: frozenset[str] = frozenset("0123456789abcdef")

# Key and signature sizes

PUBLIC_KEY_BYTES: int = 32
PRIVATE_SEED_BYTES: int = 32
SIGNATURE_BYTES: int = 64
THUMBPRINT_HEX_CHARS: int = 64

# Proof and channel binding

EXPORTER_LENGTH: int = 32
"""RFC 9266 exporter length. Canonical name; RFC9266_LENGTH is an alias."""

RFC9266_LENGTH: int = EXPORTER_LENGTH
"""Alias for EXPORTER_LENGTH; matches RFC 9266 terminology."""

MIN_NONCE_CHARS: int = 16
MAX_NONCE_CHARS: int = 64

# Envelope and frame sizes

MAX_POP_BYTES: int = 8 * 1024
MAX_ENVELOPE_BYTES: int = MAX_POP_BYTES
"""Alias: the PoP and enrollment envelopes share the same byte budget."""

MAX_TOKEN_BYTES: int = 32 * 1024
MAX_BLOCKS: int = 16

MAX_FRAME_BYTES: int = 1 << 20
"""Outer message-framing limit for transports that frame capchain
payloads. Not enforced by the wire layer itself."""

# Canonical JSON
MAX_IDENT_CHARS = 128

MAX_STRING_CHARS: int = 512
MAX_KEY_CHARS: int = 64
MAX_OBJECT_KEYS: int = 128
MAX_LIST_ITEMS: int = 256
MAX_NESTING: int = 8
MAX_DEPTH: int = MAX_NESTING
"""Alias for MAX_NESTING; both names appear in call sites."""

MAX_INT: int = 2**53
"""JSON is decoded by many languages. Anything above 2**53 loses
precision in IEEE-754 doubles, so two conforming parsers can disagree
on the value after a round-trip. RejectError rather than silently truncate."""

# Identity and context

MAX_AGENT_ID_CHARS: int = 512
MAX_SESSION_ID_CHARS: int = 128
MAX_TASK_CHARS: int = 512
MAX_CID_CHARS: int = 128
MAX_JTI_CHARS: int = 128
MAX_URI_CHARS: int = 512
MAX_RESOURCE_CHARS: int = 128
MAX_ACTION_CHARS: int = 128

# Scope

MAX_TOOLS: int = 128
MAX_DOMAINS: int = 128
MAX_AUDIENCE: int = 128

MAX_SCOPE_TOOLS: int = MAX_TOOLS
MAX_SCOPE_DOMAINS: int = MAX_DOMAINS
MAX_SCOPE_AUDIENCE: int = MAX_AUDIENCE
"""Aliases retained for call sites that use the MAX_SCOPE_* spelling."""

# Errors

MAX_DETAIL_CHARS: int = 512
MAX_RejectError_DETAIL: int = MAX_DETAIL_CHARS
"""Alias for MAX_DETAIL_CHARS."""

# Evidence

MAX_EVIDENCE_WINDOW: int = 10_000
MAX_PAYLOAD_HASH_CHARS: int = 71
"""len('sha256:') + 64 hex chars."""

# Pinning

MAX_PIN_VALUE_BYTES: int = 4096

# Field-set shapes

_DELEGATION_BASE = frozenset({
    "ver", "typ", "cid", "jti", "iss", "holder", "cnf", "sid",
    "task", "scope", "nbf", "exp", "max_depth", "prev", "model",
})
BLOCK_FIELDS:     frozenset[str] = _DELEGATION_BASE                     # delegation blocks
AUTHORITY_FIELDS: frozenset[str] = _DELEGATION_BASE | {"enrollment_receipt"}  # block 0 only

POP_FIELDS: frozenset[str] = frozenset(
    {"ver", "typ", "aud", "ath", "res", "act", "ph", "ts", "nonce", "cb"}
)
ENROLL_FIELDS: frozenset[str] = frozenset({"ver", "typ", "aud", "cb", "ts"})
SCOPE_FIELDS: frozenset[str] = frozenset(
    {"tools", "budget", "domains", "audience"})


class Code(StrEnum):
    """Stable, machine-readable outcome codes."""

    OK = "OK"
    SETTLED = "SETTLED"

    # Encoding
    CANONICAL_FORM = "CANONICAL_FORM"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"

    # Token / chain
    TOKEN_MALFORMED = "TOKEN_MALFORMED"
    TOKEN_TOO_LARGE = "TOKEN_TOO_LARGE"
    TOKEN_SIGNATURE = "TOKEN_SIGNATURE"
    TOKEN_NOT_YET_VALID = "TOKEN_NOT_YET_VALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    HOLDER_MISMATCH = "HOLDER_MISMATCH"
    CONTEXT_DRIFT = "CONTEXT_DRIFT"
    SCOPE_WIDENED = "SCOPE_WIDENED"
    TOO_DEEP = "TOO_DEEP"
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"
    MODEL_MISMATCH = "MODEL_MISMATCH"

    # Proof of possession
    POP_REQUIRED = "POP_REQUIRED"
    POP_MALFORMED = "POP_MALFORMED"
    POP_MISMATCH = "POP_MISMATCH"
    POP_BAD_SIGNATURE = "POP_BAD_SIGNATURE"
    POP_STALE = "POP_STALE"
    POP_BINDING = "POP_BINDING"
    CB_MISMATCH = "CB_MISMATCH"

    # Authorization
    POLICY_DENIED = "POLICY_DENIED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    WRONG_HOLDER = "WRONG_HOLDER"
    WRONG_AUDIENCE = "WRONG_AUDIENCE"
    WRONG_SESSION = "WRONG_SESSION"
    WRONG_TASK = "WRONG_TASK"
    NOT_ENROLLED = "NOT_ENROLLED"

    # State
    REVOKED = "REVOKED"
    REPLAY = "REPLAY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BUDGET_CAP_CHANGED = "BUDGET_CAP_CHANGED"
    STATE_UNAVAILABLE = "STATE_UNAVAILABLE"
    EVIDENCE_BROKEN = "EVIDENCE_BROKEN"
    INTERNAL = "INTERNAL"
    ENROLLMENT_EXPIRED = "ENROLLMENT_EXPIRED"
    ENROLLMENT_BAD_SIGNATURE = "ENROLLMENT_BAD_SIGNATURE"
    ENROLLMENT_MISMATCH = "ENROLLMENT_MISMATCH"
    ENROLLMENT_MALFORMED = "ENROLLMENT_MALFORMED"

    TOO_FEW_SIGNATURES = "TOO_FEW_SIGNATURES"   

class Model:
    """How a token is bound to its presenter."""

    PEER_BOUND = "peer_bound"
    """mTLS peer identity must equal the leaf holder. No per-request proof."""

    KEY_BOUND = "key_bound"
    """PEER_BOUND plus a single-use proof of possession on every request."""


MODELS = frozenset({Model.PEER_BOUND, Model.KEY_BOUND})


def _printable(text: str) -> str:
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in text)


class RejectError(Exception):
    """Raised for every authorization or protocol failure.

    `code` is stable and safe to branch on. `detail` is sanitized ASCII
    intended for operators, not for callers to parse.
    """

    __slots__ = ("code", "detail")

    def __init__(
        self,
        code: Code,
        detail: str = "",
        *,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = _printable(detail)[:MAX_DETAIL_CHARS]
        if cause is not None:
            self.__cause__ = cause



def error(
    code: Code,
    detail: str = "",
    *,
    cause: Optional[BaseException] = None,
) -> RejectError:
    return RejectError(code, detail,  cause=cause)

 
def _RejectError_float(text: str) -> None:
    raise RejectError(
        Code.CANONICAL_FORM,
        f"floats not permitted: {text!r}",
    )


def _RejectError_constant(text: str) -> None:
    raise RejectError(
        Code.CANONICAL_FORM,
        f"non-finite: {text!r}",
    )


def _RejectError_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise RejectError(
                Code.CANONICAL_FORM,
                f"duplicate key: {key!r}",
            )
        seen.add(key)
    return dict(pairs)


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def _bounded_int(s: str) -> int:
    if len(s.lstrip("-")) > 16:
        raise RejectError(
            Code.CANONICAL_FORM,
            "integer too large",
        )
    n = int(s)
    if abs(n) > MAX_INT:
        raise RejectError(
            Code.CANONICAL_FORM,
            "integer out of safe range",
        )
    return n


def _validate(value: Any, depth: int = 0) -> None:
    if depth > MAX_NESTING:
        raise RejectError(
            Code.CANONICAL_FORM,
            "nesting too deep",
        )
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise RejectError(
                Code.CANONICAL_FORM,
                "integer out of safe range",
            )
        return
    if isinstance(value, float):
        raise RejectError(Code.CANONICAL_FORM, "float")
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise RejectError(
                Code.CANONICAL_FORM,
                "string too long",
            )
        if _has_surrogate(value):
            raise RejectError(
                Code.CANONICAL_FORM,
                "unpaired surrogate",
            )
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_ITEMS:
            raise RejectError(
                Code.CANONICAL_FORM,
                "list too long",
            )
        for item in value:
            _validate(item, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            raise RejectError(
                Code.CANONICAL_FORM,
                "object too large",
            )
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > MAX_KEY_CHARS:
                raise RejectError(Code.CANONICAL_FORM, "bad key")
            if _has_surrogate(key):
                raise RejectError(
                    Code.CANONICAL_FORM,
                    "surrogate in key",
                )
            _validate(item, depth + 1)
        return
    raise RejectError(
        Code.CANONICAL_FORM,
        f"unserialisable {type(value).__name__}",
    )

def _normalize(name: str, values: Iterable[str], limit: int) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{name} must be a collection of strings, not a string")
    result = frozenset(values)
    for item in result:
        if not isinstance(item, str) or not item or len(item) > MAX_STRING_CHARS:
            raise ValueError(f"{name} must contain non-empty strings")
    if ANY in result and len(result) != 1:
        raise ValueError(f"{name}: '{ANY}' must be the only member")
    if len(result) > limit:
        raise ValueError(f"too many {name}")
    return result

def _str_set(name: str, values) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{name} must be an iterable, not a single value")
    try:
        out = frozenset(values)
    except TypeError as e:
        raise ValueError(f"bad {name}") from e
    if not all(isinstance(x, str) and 0 < len(x) <= MAX_STRING_CHARS for x in out):
        raise ValueError(f"{name}: non-empty strings only")
    return out

def encode(obj: dict) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, integers only."""
    _validate(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def decode(raw: bytes) -> dict:
    """Parse canonical JSON, RejectErroring any non-canonical spelling."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RejectError(Code.CANONICAL_FORM, f"utf8: {exc}") from None
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_RejectError_duplicates,
            parse_float=_RejectError_float,
            parse_constant=_RejectError_constant,
            parse_int=_bounded_int,
        )
    except RejectError:
        raise
    except Exception as exc:
        raise RejectError(Code.CANONICAL_FORM, f"json: {exc}") from None
    if not isinstance(obj, dict):
        raise RejectError(Code.CANONICAL_FORM, "not an object")
    if encode(obj) != raw:
        raise RejectError(Code.CANONICAL_FORM, "not canonical")
    return obj


def loads_strict(raw: bytes) -> Any:
    """Envelope parser. Canonicality is enforced by re-encoding the result."""
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_RejectError_duplicates,
        parse_float=_RejectError_float,
        parse_constant=_RejectError_constant,
        parse_int=_bounded_int,
    )


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise RejectError(
            Code.CANONICAL_FORM,
            "b64 input must be str",
        )
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise RejectError(Code.CANONICAL_FORM, f"b64: {exc}") from None
    if b64e(raw) != text:
        raise RejectError(
            Code.CANONICAL_FORM,
            "non-canonical b64",
        )
    return raw


def sha256_tag(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(bytes(data)).hexdigest()


def bounded_str(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit


def is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)

def thumbprint(public_key: bytes) -> str:
    """SHA-256 of a raw Ed25519 public key, lowercase hex."""
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_BYTES:
        raise ValueError(f"public key must be {PUBLIC_KEY_BYTES} raw bytes")
    return hashlib.sha256(public_key).hexdigest()


def is_thumbprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == THUMBPRINT_HEX_CHARS
        and all(c in HEX for c in value)
    )


def domain_separate(context: str | bytes, message: bytes) -> bytes:
    if isinstance(context, str):
        context = context.encode("ascii")
    return context + b"\x00" + message


def verify_signature(
    public_key: bytes,
    signature: bytes,
    context: bytes,
    message: bytes,
    code: Code,
    detail: str,
) -> None:
    """Verify an Ed25519 signature under a domain-separation context."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, domain_separate(context, message)
        )
    except (InvalidSignature, ValueError):
        raise RejectError(code, detail) from None # type: ignore



class CapChainKey:
    """An Ed25519 key belonging to one workload.

    Generate at boot and enroll it, or load a 32-byte seed from secure
    storage for a long-lived root. `agent_id` is optional metadata; the
    binding that matters is `thumbprint == parent block's cnf`.
    """

    __slots__ = (
        "_private",
        "_public",
        "_thumbprint",
        "agent_id",
    )

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        agent_id: str | None = None,
    ) -> None:
        self._private = private_key
        self._public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self._thumbprint = thumbprint(self._public)
        self.agent_id = agent_id

    @classmethod
    def generate(cls, *, agent_id: str | None = None) -> CapChainKey:
        return cls(
            Ed25519PrivateKey.generate(),
            agent_id=agent_id,
        )

    @classmethod
    def from_seed(
        cls,
        seed: bytes,
        *,
        agent_id: str | None = None,
    ) -> CapChainKey:
        if not isinstance(seed, bytes) or len(seed) != PRIVATE_SEED_BYTES:
            raise ValueError(f"seed must be {PRIVATE_SEED_BYTES} bytes")
        return cls(
            Ed25519PrivateKey.from_private_bytes(seed),
            agent_id=agent_id,
        )

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def thumbprint(self) -> str:
        """The value that appears as `cnf` in a token block."""
        return self._thumbprint

    def sign(self, context: bytes, message: bytes) -> bytes:
        """Internal: sign under a domain-separation context."""
        return self._private.sign(domain_separate(context, message))

    def __repr__(self) -> str:
        return f"WorkloadKey(agent_id={self.agent_id!r}, thumbprint={self._thumbprint[:16]}...)"



class TrustedRoots:
    """Root issuer IDs mapped to their raw Ed25519 public keys.

    This is the only key material a gateway needs. Intermediate workloads
    are authenticated by the chain itself.
    """

    __slots__ = ("_by_thumbprint","enrollment_authority_key")

    def __init__(
        self,
        enrollment_authority_key:bytes,
        issuers: Mapping[str, bytes | Iterable[bytes]],
    ) -> None:
        self._by_thumbprint: dict[str, tuple[str, bytes]] = {}
        if not isinstance(enrollment_authority_key, (bytes, bytearray)):
            raise ValueError("enrollment_authority_key must be raw bytes")
        raw_ea = bytes(enrollment_authority_key)
        if len(raw_ea) != PUBLIC_KEY_BYTES:
            raise ValueError(f"enrollment_authority_key must be {PUBLIC_KEY_BYTES} bytes")
        self.enrollment_authority_key: bytes = raw_ea

        for issuer_id, keys in issuers.items():
            if not isinstance(issuer_id, str) or not issuer_id:
                raise ValueError("issuer ID must be a non-empty string")

            key_list = [keys] if isinstance(keys, (bytes, bytearray)) else list(keys)
            if not key_list:
                raise ValueError(f"{issuer_id}: at least one key required")
            
            for key in key_list:
                if not isinstance(key, (bytes, bytearray)):
                    raise ValueError(f"{issuer_id}: keys must be raw bytes")
                raw = bytes(key)
                if len(raw) != PUBLIC_KEY_BYTES:
                    raise ValueError(f"{issuer_id}: key must be {PUBLIC_KEY_BYTES} bytes")
                kid = thumbprint(raw)
                existing = self._by_thumbprint.get(kid)
                if existing is not None and existing[0] != issuer_id:
                    raise ValueError(f"key bound to both {existing[0]} and {issuer_id}")
                self._by_thumbprint[kid] = (
                    issuer_id,
                    raw,
                )

    def issuer_for(self, public_key: bytes) -> str | None:
        entry = self._by_thumbprint.get(thumbprint(public_key))
        if entry is None or not hmac.compare_digest(entry[1], public_key):
            return None
        return entry[0]

    def as_wire_config(
        self,
    ) -> dict[str, list[str]]:
        """Base64 view, for writing config files or logs."""
        out: dict[str, list[str]] = {}
        for (
            issuer_id,
            raw,
        ) in self._by_thumbprint.values():
            out.setdefault(issuer_id, []).append(b64e(raw))
        return out


@dataclass(frozen=True, slots=True)
class Block:
    """One link in a capability chain."""

    body_raw: bytes
    signature: bytes
    signer_public_key: bytes

    def body(self) -> dict:
        return decode(self.body_raw)

    @staticmethod
    def link_hash(block: Block) -> str:
        """Length-prefixed hash binding a block to its successor's `prev`."""

        def framed(data: bytes) -> bytes:
            return len(data).to_bytes(4, "big") + data

        return hashlib.sha256(
            LINK_LABEL
            + framed(block.body_raw)
            + framed(block.signature)
            + framed(block.signer_public_key)
        ).hexdigest()

    def to_b64e(self) -> dict:
        return   {
            "b": b64e(self.body_raw),
            "s": b64e(self.signature),
            "k": b64e(self.signer_public_key),
        }

    @classmethod
    def from_b64d(cls, entry) -> "Block":
        return cls(
                b64d(entry["b"]),
                b64d(entry["s"]),
                b64d(entry["k"]),
            )

def link_hash(block: Block) -> str:
    """Length-prefixed hash binding a block to its successor's `prev`."""

    def framed(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    return hashlib.sha256(
        LINK_LABEL
        + framed(block.body_raw)
        + framed(block.signature)
        + framed(block.signer_public_key)
    ).hexdigest()


def sign_block(key: CapChainKey, body: dict) -> Block:
    raw = encode(body)
    return Block(
        raw,
        key.sign(CTX_BLOCK, raw),
        key.public_key,
    )




@dataclass(frozen=True, slots=True)
class Scope:
    """What a token permits.

    tools      "resource:action" strings the request must match.
    audience   verifier IDs allowed to accept the token. Never empty.
    domains    target hosts. Empty means no domain access; {"*"} means any.
    budget     spend ceiling in micros for this hop.

    Narrowing is monotone: a subset scope never grants more than its parent.
    """

    tools: frozenset[str]
    budget_micros: int
    audience: frozenset[str]
    domains: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "tools",
            _normalize("tools", self.tools, MAX_TOOLS),
        )
        object.__setattr__(
            self,
            "audience",
            _normalize(
                "audience",
                self.audience,
                MAX_AUDIENCE,
            ),
        )
        object.__setattr__(
            self,
            "domains",
            _normalize(
                "domains",
                self.domains,
                MAX_DOMAINS,
            ),
        )
        if not self.audience:
            raise ValueError("audience must not be empty")
        if type(self.budget_micros) is not int or self.budget_micros < 0:
            raise ValueError("budget_micros must be a non-negative int")
        if self.budget_micros > MAX_INT:
            raise ValueError(f"budget_micros must be <= {MAX_INT}")

    def allows_tool(self, tool: str) -> bool:
        return ANY in self.tools or tool in self.tools

    def allows_verifier(self, verifier_id: str) -> bool:
        return ANY in self.audience or verifier_id in self.audience

    def allows_domain(self, host: str) -> bool:
        return ANY in self.domains or host in self.domains

    def is_subset_of(self, parent: Scope) -> bool:
        if ANY not in parent.tools and not self.tools <= parent.tools:
            return False
        if self.budget_micros > parent.budget_micros:
            return False
        if ANY not in parent.domains and not self.domains <= parent.domains:
            return False
        return not (ANY not in parent.audience and not self.audience <= parent.audience)

    def to_body(self) -> dict:
        return {
            "tools": sorted(self.tools),
            "budget": self.budget_micros,
            "domains": sorted(self.domains),
            "audience": sorted(self.audience),
        }

    @staticmethod
    def from_body(body: object) -> Scope:
        if not isinstance(body, dict) or set(body) != SCOPE_FIELDS:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                "scope shape",
            )

        sets: dict[str, frozenset[str]] = {}
        for name in (
            "tools",
            "domains",
            "audience",
        ):
            values = body[name]
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    f"scope.{name}",
                )
            if values != sorted(set(values)):
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    f"scope.{name} not sorted/unique",
                )
            sets[name] = frozenset(values)

        budget = body["budget"]
        if type(budget) is not int:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                "scope.budget",
            )

        try:
            return Scope(
                tools=sets["tools"],
                budget_micros=budget,
                audience=sets["audience"],
                domains=sets["domains"],
            )
        except ValueError as exc:
            raise RejectError(Code.TOKEN_MALFORMED, str(exc)) from None

def derive_jti(prev_link: str, issuer: str, scope: Scope) -> str:
    """Content-addressed jti: siblings from the same (parent block, issuer,
    scope) share one ledger hop, so a delegator's total spend in a given
    scope is bounded by that scope's budget even when split across children.
    """
    h = hashlib.sha256()
    h.update(f"capchain/{WIRE}/attenuate-jti\x00".encode("ascii"))
    h.update(prev_link.encode("ascii"))
    h.update(b"\x00")
    h.update(issuer.encode("utf-8"))
    h.update(b"\x00")
    h.update(encode(scope.to_body()))
    return h.hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Token:
    """An ordered chain of blocks. Encodes to exactly one byte sequence."""

    blocks: tuple[Block, ...]

    @property
    def root(self):
        return self.blocks[0]
    
    @property
    def leaf(self):
        return self.blocks[-1]

    def encode(self) -> bytes:
        return json.dumps(
            {
                "v": WIRE_VERSION,
                "blocks": [b.to_b64e() for b in self.blocks],
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    @staticmethod
    def decode(raw: bytes) -> Token:
        if not isinstance(raw, (bytes, bytearray)):
            raise RejectError(
                Code.TOKEN_MALFORMED,
                "token must be bytes",
            )
        raw = bytes(raw)
        if len(raw) > MAX_TOKEN_BYTES:
            raise RejectError(
                Code.TOKEN_TOO_LARGE,
                str(len(raw)),
            )

        try:
            document = loads_strict(raw)
        except RejectError as exc:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                f"json: {exc.detail or exc.code}",
            ) from None
        except Exception as exc:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                f"json: {type(exc).__name__}",
            ) from None

        if not isinstance(document, dict) or set(document) != {"v", "blocks"}:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                "envelope shape",
            )
        if not is_int(document["v"]):
            raise RejectError(
                Code.TOKEN_MALFORMED,
                "version must be int",
            )
        if document["v"] != WIRE_VERSION:
            raise RejectError(
                Code.VERSION_UNSUPPORTED,
                f"v={document['v']}",
            )

        raw_blocks = document["blocks"]
        if not isinstance(raw_blocks, list) or not 1 <= len(raw_blocks) <= MAX_BLOCKS:
            raise RejectError(Code.TOKEN_MALFORMED, "block list")

        blocks: list[Block] = []
        for index, entry in enumerate(raw_blocks):
            if not isinstance(entry, dict) or set(entry) != {"b", "s", "k"}:
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    f"block {index} shape",
                )
            try:
                block = Block.from_b64d(entry)
            except RejectError as exc:
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    f"block {index}: {exc.code}",
                ) from None
            if (
                len(block.signature) != SIGNATURE_BYTES
                or len(block.signer_public_key) != PUBLIC_KEY_BYTES
            ):
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    f"block {index} lengths",
                )
            blocks.append(block)

        token = Token(tuple(blocks))
        if token.encode() != raw:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                "non-canonical envelope",
            )
        return token


@dataclass(frozen=True, slots=True)
class Signed:
    """A detached signed body: proof of possession or enrollment."""

    body_raw: bytes
    signature: bytes
    public_key: bytes

    def encode(self) -> bytes:
        return json.dumps(
            {
                "b": b64e(self.body_raw),
                "s": b64e(self.signature),
                "k": b64e(self.public_key),
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    @staticmethod
    def decode(raw: bytes) -> Signed:
        if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_ENVELOPE_BYTES:
            raise RejectError(Code.POP_MALFORMED, "size")
        raw = bytes(raw)
        try:
            document = loads_strict(raw)
            if not isinstance(document, dict) or set(document) != {"b", "s", "k"}:
                raise RejectError(Code.POP_MALFORMED, "shape")
            envelope = Signed(
                b64d(document["b"]),
                b64d(document["s"]),
                b64d(document["k"]),
            )
        except RejectError as exc:
            raise RejectError(
                Code.POP_MALFORMED,
                exc.detail or exc.code,
            ) from None
        except Exception as exc:
            raise RejectError(
                Code.POP_MALFORMED,
                type(exc).__name__,
            ) from None

        if (
            len(envelope.signature) != SIGNATURE_BYTES
            or len(envelope.public_key) != PUBLIC_KEY_BYTES
        ):
            raise RejectError(Code.POP_MALFORMED, "lengths")
        if envelope.encode() != raw:
            raise RejectError(
                Code.POP_MALFORMED,
                "non-canonical envelope",
            )
        return envelope


def _require_text(value: str, name: str, limit: int) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= limit:
        raise ValueError(f"bad {name}")
    return value


def _require_channel_binding(
    value: object,
) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != EXPORTER_LENGTH:
        raise RejectError(
            Code.CB_MISMATCH,
            "channel binding required",
        )
    return bytes(value)

def _check_timestamp(value: object, now: int, max_skew: int) -> None:
    if not is_int(value):
        raise RejectError(Code.POP_MALFORMED, "ts")
    if abs(now - value) > max_skew: # type: ignore
        raise RejectError(
            Code.POP_STALE,
            f"ts={value} now={now}",
        )

def _check_channel_binding(body: dict, expected: object) -> None:
    binding = _require_channel_binding(expected)
    presented = body.get("cb")
    if not isinstance(presented, str) or not hmac.compare_digest(
        presented.encode("ascii", "replace"),
        b64e(binding).encode("ascii"),
    ):
        raise RejectError(Code.CB_MISMATCH, "exporter mismatch")


def make_pop(
    key: CapChainKey,
    *,
    token: bytes,
    verifier_id: str,
    resource: str,
    action: str,
    body: bytes,
    channel_binding: bytes,
    now: int,
    nonce: str | None = None,
) -> bytes:
    """Sign a single-use proof binding this request to this TLS connection."""
    _require_text(
        verifier_id,
        "verifier_id",
        MAX_AGENT_ID_CHARS,
    )
    _require_text(resource, "resource", 128)
    _require_text(action, "action", 128)
    if nonce is not None and not (
        isinstance(nonce, str) and MIN_NONCE_CHARS <= len(nonce) <= MAX_NONCE_CHARS
    ):
        raise ValueError(f"nonce must be {MIN_NONCE_CHARS}..{MAX_NONCE_CHARS} chars")
    if not is_int(now) or now < 0:
        raise ValueError("now must be a non-negative int")
    binding = _require_channel_binding(channel_binding)
    raw = encode(
        {
            "ver": WIRE_VERSION,
            "typ": "pop",
            "aud": verifier_id,
            "ath": sha256_tag(token),
            "res": resource,
            "act": action,
            "ph": sha256_tag(body),
            "ts": now,
            "nonce": nonce or secrets.token_hex(16),
            "cb": b64e(binding),
        }
    )
    return Signed(
        raw,
        key.sign(CTX_POP, raw),
        key.public_key,
    ).encode()

def verify_pop(
    envelope: Signed,
    *,
    cnf: str,
    verifier_id: str,
    token: bytes,
    resource: str,
    action: str,
    body: bytes,
    channel_binding: bytes,
    now: int,
    max_skew: int,
) -> str:
    """Verify a proof and return its nonce for single-use consumption."""
    if thumbprint(envelope.public_key) != cnf:
        raise RejectError(
            Code.POP_MISMATCH,
            "proof key is not the token cnf",
        )

    verify_signature(
        envelope.public_key,
        envelope.signature,
        CTX_POP,
        envelope.body_raw,
        Code.POP_BAD_SIGNATURE,
        "pop",
    )

    body_fields = decode(envelope.body_raw)
    if (
        set(body_fields) != POP_FIELDS
        or not is_int(body_fields["ver"])
        or body_fields["ver"] != WIRE_VERSION
        or body_fields["typ"] != "pop"
    ):
        raise RejectError(Code.POP_MALFORMED, "shape/ver/typ")

    _check_timestamp(body_fields["ts"], now, max_skew)

    for name, expected in (
        ("aud", verifier_id),
        ("ath", sha256_tag(token)),
        ("res", resource),
        ("act", action),
        ("ph", sha256_tag(body)),
    ):
        if body_fields[name] != expected:
            raise RejectError(Code.POP_BINDING, name)

    nonce = body_fields["nonce"]
    if not isinstance(nonce, str) or not MIN_NONCE_CHARS <= len(nonce) <= MAX_NONCE_CHARS:
        raise RejectError(Code.POP_MALFORMED, "nonce")

    _check_channel_binding(body_fields, channel_binding)
    return nonce


def make_enrollment(
    key: CapChainKey,
    *,
    issuer_id: str,
    channel_binding: bytes,
    now: int,
) -> bytes:
    """Sign a proof that this workload controls this key on this connection."""
    _require_text(issuer_id, "issuer_id", MAX_AGENT_ID_CHARS)
    if not is_int(now) or now < 0:
        raise ValueError("now must be a non-negative int")
    raw = encode(
        {
            "ver": WIRE_VERSION,
            "typ": "enroll",
            "aud": issuer_id,
            "cb": b64e(_require_channel_binding(channel_binding)),
            "ts": now,
        }
    )
    return Signed(
        raw,
        key.sign(CTX_ENROLL, raw),
        key.public_key,
    ).encode()


def verify_enrollment(
    raw: bytes,
    *,
    issuer_id: str,
    channel_binding: bytes,
    now: int,
    max_skew: int = 30,
) -> str:
    """Verify an enrollment proof and return the key thumbprint.

    The caller binds the returned thumbprint to the TLS peer identity; this
    function never sees, and must never be given, a caller-supplied identity.
    """
    envelope = Signed.decode(raw)
    verify_signature(
        envelope.public_key,
        envelope.signature,
        CTX_ENROLL,
        envelope.body_raw,
        Code.POP_BAD_SIGNATURE,
        "enroll",
    )

    body = decode(envelope.body_raw)
    if (
        set(body) != ENROLL_FIELDS
        or not is_int(body["ver"])
        or body["ver"] != WIRE_VERSION
        or body["typ"] != "enroll"
        or body["aud"] != issuer_id
    ):
        raise RejectError(
            Code.POP_BINDING,
            "enroll shape/ver/typ/aud",
        )

    _check_timestamp(body["ts"], now, max_skew)
    _check_channel_binding(body, channel_binding)
    return thumbprint(envelope.public_key)


# Minting, attenuation, and chain verification.

@dataclass(frozen=True, slots=True)
class Verdict:
    """Everything a verifier learns from a cryptographically valid chain."""

    model: str
    cid: str
    issuer: str
    holder: str
    cnf: str
    path: tuple[str, ...]
    jtis: tuple[str, ...]
    kids: tuple[str, ...]
    budget_path: BudgetPath
    scope: Scope
    root_scope: Scope
    session_id: str
    task: str
    expires_at: int
    depth: int

@dataclass(frozen=True, slots=True)
class EnrolledKey:
    holder: str
    key_thumbprint: str
    receipt: bytes
    valid_until: int



def derive_cid(holder: str, session_id: str) -> str:
    """Content-addressed chain ID: one budget pool per (holder, session).

    Minting the same session twice yields the same cid, so the 's
    ledger aggregates spend across all such tokens. This closes the
    budget-multiplication gap where a compromised issuer mints N tokens
    for the same (holder, session), each with a fresh cid, and spends
    N * budget_micros.
    """
    h = hashlib.sha256()
    h.update(f"capchain/{WIRE}/chain-id\x00".encode("ascii"))
    h.update(holder.encode("utf-8"))
    h.update(b"\x00")
    h.update(session_id.encode("utf-8"))
    return h.hexdigest()[:32]


def make_enrollment_receipt(
    enrollment_key: CapChainKey,
    *,
    holder: str,
    cnf: str,
    ttl_seconds: int = MAX_RECEIPT_TTL_SECONDS,
    now: int,
) -> bytes:
    """Issue a receipt. Only the enrollment service holds `enrollment_key`."""
    if not is_int(now) or now < 0:
        raise ValueError("now must be a non-negative int")
    
    if not bounded_str(holder, MAX_AGENT_ID_CHARS) or not is_thumbprint(cnf):
        raise ValueError("bad holder or cnf")
    if not (is_int(ttl_seconds) and 0 < ttl_seconds <= MAX_RECEIPT_TTL_SECONDS):
        raise ValueError("bad ttl_seconds")
    raw = encode({
        "ver": WIRE_VERSION,
        "typ": "enrollment",
        "holder": holder,
        "cnf": cnf,
        "nbf": now,
        "exp": now + ttl_seconds,
    })
    return Signed(
        raw,
        enrollment_key.sign(ENROLLMENT_CTX, raw),
        enrollment_key.public_key,
    ).encode()


def verify_enrollment_receipt(
    receipt: bytes,
    *,
    expected_holder: str,
    expected_cnf: str,
    verifier: bytes,
    now: int,
    max_skew: int = 30,
) -> None:
    """Verify a receipt. Called from mint and verify_chain."""
    envelope = Signed.decode(receipt)
    if not hmac.compare_digest(envelope.public_key, verifier):
        raise RejectError(Code.ENROLLMENT_MISMATCH, "receipt signer")
    verify_signature(
        envelope.public_key, envelope.signature,
        ENROLLMENT_CTX, envelope.body_raw,
        Code.ENROLLMENT_BAD_SIGNATURE, "receipt",
    )
    body = decode(envelope.body_raw)
    if set(body) != ENROLLMENT_RECEIPT_FIELDS or body["typ"] != "enrollment":
        raise RejectError(Code.ENROLLMENT_MALFORMED, "shape")
    if body["holder"] != expected_holder:
        raise RejectError(Code.ENROLLMENT_MISMATCH, "holder")
    if body["cnf"] != expected_cnf:
        raise RejectError(Code.ENROLLMENT_MISMATCH, "cnf")
    if now + max_skew < body["nbf"]:
        raise RejectError(Code.ENROLLMENT_MALFORMED, "not yet valid")
    if now - max_skew > body["exp"]:
        raise RejectError(Code.ENROLLMENT_EXPIRED, "expired")
    if (
        set(body) != ENROLLMENT_RECEIPT_FIELDS
        or not is_int(body["ver"])
        or body["ver"] != WIRE_VERSION
        or body["typ"] != "enrollment"
    ):
        raise RejectError(Code.ENROLLMENT_MALFORMED, "shape/ver/typ")

def mint(
    root_key: CapChainKey,
    enrolled_key: EnrolledKey,  
    enrollment_verifier: bytes,
    *,
    issuer: str,
    holder: str,
    cnf: str,
    session_id: str,
    task: str,
    scope: Scope,
    ttl_seconds: int,
    now: int,
    max_depth: int = 1,
) -> Token:
    """Create a root token. Callers should use TokenIssuer, which also
    enforces that `cnf` is enrolled for `holder`."""

    verify_enrollment_receipt(
        enrolled_key.receipt,
        expected_holder=enrolled_key.holder,
        expected_cnf=enrolled_key.key_thumbprint,
        verifier=enrollment_verifier,
        now=now,
    )
    if not (
        bounded_str(issuer, MAX_AGENT_ID_CHARS)
        and bounded_str(holder, MAX_AGENT_ID_CHARS)
        and bounded_str(session_id, MAX_SESSION_ID_CHARS)
        and bounded_str(task, MAX_TASK_CHARS)
    ):
        raise ValueError("bad identity or context field")
    if not is_thumbprint(cnf):
        raise ValueError("cnf must be 64 lowercase hex characters")

    if not isinstance(scope, Scope):
        raise ValueError("scope must be a Scope")
    if not (is_int(ttl_seconds) and ttl_seconds > 0):
        raise ValueError("ttl_seconds must be a positive int")
    if not (is_int(now) and now >= 0):
        raise ValueError("now must be a non-negative int")
    if not (is_int(max_depth) and 0 <= max_depth < MAX_BLOCKS):
        raise ValueError("max_depth out of range")
    if holder != enrolled_key.holder or cnf != enrolled_key.key_thumbprint:
        raise ValueError("enrolled_key does not match holder/cnf")

    cid = derive_cid(holder, session_id)
    return Token(
        (
            sign_block(
                root_key,
                {
                    "ver": WIRE_VERSION,
                    "typ": "authority",
                    "cid": cid,
                    "jti": cid,
                    "iss": issuer,
                    "holder": holder,
                    "cnf": cnf,
                    "sid": session_id,
                    "task": task,
                    "scope": scope.to_body(),
                    "nbf": now,
                    "exp": now + ttl_seconds,
                    "max_depth": max_depth,
                    "prev": GENESIS_LINK,
                    "model": Model.KEY_BOUND,
                    "enrollment_receipt": b64e(enrolled_key.receipt),  # NEW

                },
            ),
        )
    )

def attenuate(
    parent: Token,
    key: CapChainKey,
    *,
    holder: str,
    cnf: str,
    scope: Scope,
    ttl_seconds: int,
    now: int,
) -> Token:
    """Append a narrowed delegation block signed by the current holder."""
    if not parent.blocks:
        raise RejectError(Code.TOKEN_MALFORMED, "empty parent")
    if not bounded_str(holder, MAX_AGENT_ID_CHARS) or not is_thumbprint(cnf):
        raise ValueError("bad holder or cnf")
    if not isinstance(scope, Scope):
        raise ValueError("scope must be a Scope")
    if not (is_int(ttl_seconds) and ttl_seconds > 0) or not is_int(now):
        raise ValueError("bad ttl_seconds or now")

    leaf = parent.leaf
    body = leaf.body()

    # Field set is typ-dependent: only block 0 carries the enrollment receipt.
    is_authority = len(parent.blocks) == 1
    expected = AUTHORITY_FIELDS if is_authority else BLOCK_FIELDS
    if set(body) != expected:
        raise RejectError(Code.TOKEN_MALFORMED, "parent leaf field set")

    if not bounded_str(body.get("holder"), MAX_AGENT_ID_CHARS):
        raise RejectError(Code.TOKEN_MALFORMED, "parent leaf holder")
    for name in ("max_depth", "nbf", "exp"):
        if not is_int(body[name]):
            raise RejectError(Code.TOKEN_MALFORMED, f"parent leaf {name}")

    if key.thumbprint != body["cnf"]:
        raise RejectError(Code.HOLDER_MISMATCH, "signing key is not the leaf cnf")
    if key.agent_id is not None and key.agent_id != body["holder"]:
        raise RejectError(
            Code.HOLDER_MISMATCH,
            f"key agent_id {key.agent_id} != leaf holder {body['holder']}",
        )
    if len(parent.blocks) > body["max_depth"]:
        raise RejectError(Code.TOO_DEEP, "max_depth reached")

    if not scope.is_subset_of(Scope.from_body(body["scope"])):
        raise RejectError(
            Code.SCOPE_WIDENED,
            "child scope exceeds parent",
        )

    expires_at = min(body["exp"], now + ttl_seconds)
    if expires_at <= now:
        raise RejectError(
            Code.TOKEN_EXPIRED,
            "parent already expired",
        )

    prev = link_hash(leaf)
    jti = derive_jti(prev, body["holder"], scope)

    return Token(
        (
            *parent.blocks,
            sign_block(
                key,
                {
                    "ver": WIRE_VERSION,
                    "typ": "delegation",
                    "cid": body["cid"],
                    "jti": jti,
                    "iss": body["holder"],
                    "holder": holder,
                    "cnf": cnf,
                    "sid": body["sid"],
                    "task": body["task"],
                    "scope": scope.to_body(),
                    "nbf": max(now, body["nbf"]),
                    "exp": expires_at,
                    "max_depth": body["max_depth"],
                    "prev": prev,
                    "model": body["model"],
                },
            ),
        )
    )

def verify_chain(
    raw_token: bytes,
    *,
    roots: TrustedRoots,
    now: int,
    max_depth: int,
    skew: int = 0,
) -> Verdict:
    """Validate signatures, linkage, monotonicity, and validity windows.

    Raises RejectError on any failure. Performs no policy, state, or request
    checks; those belong to the Gateway.
    """
    if not is_int(skew) or skew < 0:
        raise ValueError("skew must be a non-negative int")
    token = Token.decode(raw_token)
    depth = len(token.blocks) - 1
    if depth > max_depth:
        raise RejectError(
            Code.TOO_DEEP,
            f"depth {depth} exceeds policy {max_depth}",
        )
    previous: dict | None = None
    previous_scope: Scope | None = None
    root_scope: Scope | None = None
    previous_link = GENESIS_LINK
    previous_nbf = previous_exp = 0

    path: list[str] = []
    jtis: list[str] = []
    kids: list[str] = []
    budget_path: list[tuple[str, int]] = []
    model = cid = session_id = task = ""

    for index, block in enumerate(token.blocks):
        # Authenticate before interpreting anything in the body.
        verify_signature(
            block.signer_public_key,
            block.signature,
            CTX_BLOCK,
            block.body_raw,
            Code.TOKEN_SIGNATURE,
            f"block {index}",
        )
        body = block.body()
        expected = AUTHORITY_FIELDS if index == 0 else BLOCK_FIELDS
        if set(body) != expected:
            raise RejectError(Code.TOKEN_MALFORMED, f"block {index} field set")

        if not is_int(body["ver"]):
            raise RejectError(
                Code.TOKEN_MALFORMED,
                f"block {index} ver type",
            )
        if body["ver"] != WIRE_VERSION:
            raise RejectError(
                Code.VERSION_UNSUPPORTED,
                f"block {index}",
            )
        if body["prev"] != previous_link:
            raise RejectError(
                Code.CHAIN_BROKEN,
                f"block {index}",
            )

        issuer = body["iss"]
        holder = body["holder"]
        jti = body["jti"]
        cnf = body["cnf"]
        if not (
            bounded_str(issuer, MAX_AGENT_ID_CHARS)
            and bounded_str(holder, MAX_AGENT_ID_CHARS)
            and bounded_str(jti, MAX_JTI_CHARS)
            and is_thumbprint(cnf)
        ):
            raise RejectError(
                Code.TOKEN_MALFORMED,
                f"block {index} fields",
            )

        if index == 0:
            if body["typ"] != "authority":
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    "block 0 typ",
                )
            if roots.issuer_for(block.signer_public_key) != issuer:
                raise RejectError(
                    Code.UNKNOWN_ISSUER,
                    f"root key not bound to {issuer}",
                )
            receipt_b64 = body.get("enrollment_receipt")
            if not receipt_b64:
                raise RejectError(Code.TOKEN_MALFORMED, "missing enrollment receipt")
            verify_enrollment_receipt(
                b64d(receipt_b64),
                expected_holder=body["holder"],
                expected_cnf=body["cnf"],
                verifier=roots.enrollment_authority_key,
                now=now,
                max_skew=skew,
            )

            model = body["model"]
            if model not in MODELS:
                raise RejectError(
                    Code.MODEL_MISMATCH,
                    f"block 0 model {model!r}",
                )

            cid, session_id, task = (
                body["cid"],
                body["sid"],
                body["task"],
            )
            if not (
                bounded_str(cid, MAX_CID_CHARS)
                and bounded_str(
                    session_id,
                    MAX_SESSION_ID_CHARS,
                )
                and bounded_str(task, MAX_TASK_CHARS)
            ):
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    "block 0 context",
                )

            declared_depth = body["max_depth"]
            if not is_int(declared_depth) or not 0 <= declared_depth < MAX_BLOCKS:
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    "max_depth",
                )
            if depth > declared_depth:
                raise RejectError(
                    Code.TOO_DEEP,
                    f"{depth} > {declared_depth}",
                )

            path.append(issuer)
        else:
            assert previous is not None
            if body["typ"] != "delegation":
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    f"block {index} typ",
                )
            if thumbprint(block.signer_public_key) != previous["cnf"]:
                raise RejectError(
                    Code.HOLDER_MISMATCH,
                    f"block {index} signer != prev cnf",
                )
            if issuer != previous["holder"]:
                raise RejectError(
                    Code.HOLDER_MISMATCH,
                    f"block {index} iss != prev holder",
                )
            if body["model"] != model:
                raise RejectError(
                    Code.CONTEXT_DRIFT,
                    f"block {index} model",
                )
            if not is_int(body["max_depth"]) or (
                body["cid"],
                body["sid"],
                body["task"],
                body["max_depth"],
            ) != (
                cid,
                session_id,
                task,
                previous["max_depth"],
            ):
                raise RejectError(
                    Code.CONTEXT_DRIFT,
                    f"block {index}",
                )

        if holder != path[-1]:
            path.append(holder)
        scope = Scope.from_body(body["scope"])
        if previous_scope is not None and not scope.is_subset_of(previous_scope):
            raise RejectError(
                Code.SCOPE_WIDENED,
                f"block {index}",
            )
        if index == 0:
            if jti != cid:
                raise RejectError(
                    Code.TOKEN_MALFORMED,
                    "block 0 jti != cid",
                )
            root_scope = scope
        else:
            if not hmac.compare_digest(
                jti,
                derive_jti(previous_link, issuer, scope),
            ):
                raise RejectError(
                    Code.CHAIN_BROKEN,
                    f"block {index} jti",
                )

        nbf, exp = body["nbf"], body["exp"]
        if not (is_int(nbf) and is_int(exp)) or nbf < 0 or exp <= nbf:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                f"block {index} time",
            )
        if index > 0 and (nbf < previous_nbf or exp > previous_exp):
            raise RejectError(
                Code.CONTEXT_DRIFT,
                f"block {index} time widened",
            )
        if jti in jtis:
            raise RejectError(
                Code.TOKEN_MALFORMED,
                f"block {index} duplicate jti",
            )
        if now + skew < nbf:
            raise RejectError(
                Code.TOKEN_NOT_YET_VALID,
                f"block {index}: now={now} nbf={nbf} skew={skew}",
            )
        if now - skew >= exp:
            raise RejectError(
                Code.TOKEN_EXPIRED,
                f"block {index}: now={now} exp={exp} skew={skew}",
            )

        jtis.append(jti)
        kids.append(thumbprint(block.signer_public_key))
        budget_path.append((jti, scope.budget_micros))

        (
            previous,
            previous_scope,
            previous_link,
        ) = body, scope, link_hash(block)
        previous_nbf, previous_exp = nbf, exp

    assert previous is not None and previous_scope is not None and root_scope is not None

    return Verdict(
        model=model,
        cid=cid,
        issuer=path[0],
        holder=previous["holder"],
        cnf=previous["cnf"],
        path=tuple(path),
        jtis=tuple(jtis),
        kids=tuple(kids),
        budget_path=tuple(budget_path),
        scope=previous_scope,
        root_scope=root_scope,
        session_id=session_id,
        task=task,
        expires_at=previous["exp"],
        depth=depth,
    )


def make_scope(*, tools, budget_micros, audience, domains=()):
    """Build a Scope from iterables. `audience` must be non-empty.

    Argument order matches Scope's field order, so `audience` and
    `domains` are not accidentally swapped.
    """
    return Scope(
        tools=_str_set("tools", tools),
        budget_micros=budget_micros,
        audience=_str_set("audience", audience),
        domains=_str_set("domains", domains),
    )
