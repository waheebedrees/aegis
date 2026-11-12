"""
clock.py — the time authority for long-horizon agents.

Two clocks, one interface.

  WALL:       time.time(), in ms. Survives restarts. Used for token
              exp / nbf / iat, freshness windows, evidence timestamps.
              Subject to skew and NTP corrections.

  MONOTONIC:  time.monotonic(), in ms. Process-local. Never goes
              backward within a process. Used for lease TTLs,
              backoff timers, and any "elapsed since" check.

Every mutation in the kernel that binds to time must declare which
clock it uses. Nothing compares a wall timestamp to a monotonic one.
Nothing uses wall time for a lease. Nothing uses monotonic time for
an expiry that must survive a restart.

The Clock is a plane, not a singleton. It is passed into every
component that needs time; no module reaches for time.time() directly.

Corrections in this version
───────────────────────────

1. Beacon binding. `TimeBeacon` no longer accepts caller-supplied
   timestamps alongside an opaque `raw` blob. `BeaconClock` takes
   only the signed envelope bytes and derives every field from the
   verified body. A caller cannot install a beacon whose fields
   disagree with the signature.

2. Rollback protection. `BeaconClock.refresh()` rejects a beacon
   whose `t_ms` is lower than the current anchor's. A captured old
   beacon cannot overwrite a newer one.

3. Monotonic guard inside BeaconClock. A monotonic source that goes
   backward raises `ClockMonotonicity` at the boundary.

4. `_skew_ms` naming. `FixedClock` uses `_skew_ms` consistently with
   `SystemClock` and `BeaconClock`.

5. `now_seconds()` and `__call__`. Every `Clock` is callable and
   returns wall seconds. `TokenIssuer(clock=...)` accepts a `Clock`
   directly — no wrapper lambda needed. Matches capchain's
   `Callable[[], int]` time source without a bridge.

6. `ClockSkew` is raised. `require_within_skew` and `require_fresh`
   raise it on violation. `within_skew` and `is_fresh` keep returning
   bool so callers can choose their error model.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ══════════════════════════════════════════════════════════════════════════
# Exceptions
# ══════════════════════════════════════════════════════════════════════════

class ClockError(Exception):
    """Base for all clock-related failures."""


class ClockSkew(ClockError):
    """Observed skew exceeds the declared bound.

    Raised by `require_within_skew` and `require_fresh` when the
    caller's tolerance is violated. Callers with a policy that maps
    this to an authorization outcome (e.g. `Reject(POLICY_DENIED)`)
    catch `ClockSkew` and translate.

    Not raised by `within_skew` or `is_fresh`, which return bool so
    that callers can decide their own error model.
    """


class ClockBeaconInvalid(ClockError):
    """A signed time beacon failed verification, expired, drifted, or rolled back."""


class ClockMonotonicity(ClockError):
    """A monotonic source went backward. A programming error, not a race."""


# ══════════════════════════════════════════════════════════════════════════
# Clock interface
# ══════════════════════════════════════════════════════════════════════════

class Clock(ABC):
    """
    Time authority for one process.

    Contract:

      wall_ms()
          Wall clock in milliseconds since the Unix epoch. May go
          backward if the OS corrects via NTP. Comparable across
          processes within skew_ms().

      mono_ms()
          Monotonic clock in milliseconds. Never decreases within a
          process. Meaningless outside the process. Restarts reset it.

      skew_ms()
          Declared *bound* on wall_ms() error, in milliseconds. Not
          a measurement; a promise. A SystemClock(skew_ms=1000)
          reports 1000 even when the OS clock is perfect, because
          callers use this number as the tolerance to add when
          comparing timestamps from different sources.

      source_id()
          Identifier for the wall time origin. Two clocks with the
          same source_id are assumed to share a wall time basis;
          different source_ids are not directly comparable without
          an external trust anchor.

      is_trusted()
          True only when wall_ms is anchored to a verified external
          source (beacon, NTS, etc.). SystemClock is not trusted;
          BeaconClock is.

      now_seconds()
          Wall time in seconds. Alias for wall_s(). Named for
          compatibility with capchain's Callable[[], int] time
          source (TokenIssuer, Gateway).

      __call__()
          Same as now_seconds(). Makes a Clock usable anywhere a
          Callable[[], int] is expected without a wrapper.
    """

    @abstractmethod
    def wall_ms(self) -> int: ...

    @abstractmethod
    def mono_ms(self) -> int: ...

    @abstractmethod
    def skew_ms(self) -> int: ...

    @abstractmethod
    def source_id(self) -> str: ...

    def is_trusted(self) -> bool:
        return False

    def wall_s(self) -> int:
        return self.wall_ms() // 1000

    def mono_s(self) -> int:
        return self.mono_ms() // 1000

    def now_seconds(self) -> int:
        """Wall time in seconds since the epoch.

        Alias for wall_s(). Provided so a Clock can be passed directly
        to `capchain.TokenIssuer(clock=...)` and `capchain.Gateway(...)`
        which take `Callable[[], int]` returning wall seconds.
        """
        return self.wall_ms() // 1000

    def __call__(self) -> int:
        """Callable form of now_seconds(). Same value, same units."""
        return self.wall_ms() // 1000


# ══════════════════════════════════════════════════════════════════════════
# Implementations
# ══════════════════════════════════════════════════════════════════════════

class SystemClock(Clock):
    """
    Default clock. Reads time.time() and time.monotonic().

    Not trusted. The OS clock may be wrong and there is no way for
    this class to know. Use in-process, single-host deployments
    where clock skew is bounded by NTP and the caller's threat
    model accepts that.
    """

    __slots__ = ("_skew_ms",)

    def __init__(self, *, skew_ms: int = 1000) -> None:
        if isinstance(skew_ms, bool) or not isinstance(skew_ms, int):
            raise ValueError("skew_ms must be an int")
        if skew_ms < 0:
            raise ValueError("skew_ms must be >= 0")
        self._skew_ms = skew_ms

    def wall_ms(self) -> int:
        return int(time.time() * 1000)

    def mono_ms(self) -> int:
        return int(time.monotonic() * 1000)

    def skew_ms(self) -> int:
        return self._skew_ms

    def source_id(self) -> str:
        return "system"


class FixedClock(Clock):
    """
    A clock that does not advance unless told to. For tests.

    wall_ms() may be set to any value, including backward, to
    simulate NTP corrections. mono_ms() only moves forward via
    advance_ms(); attempting to move it backward raises.
    """

    __slots__ = ("_wall", "_mono", "_skew_ms")

    def __init__(
        self,
        *,
        wall_ms: int = 0,
        mono_ms: int = 0,
        skew_ms: int = 0,
    ) -> None:
        for name, value in (("wall_ms", wall_ms),
                            ("mono_ms", mono_ms),
                            ("skew_ms", skew_ms)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an int")
        self._wall = wall_ms
        self._mono = mono_ms
        self._skew_ms = skew_ms

    def wall_ms(self) -> int:
        return self._wall

    def mono_ms(self) -> int:
        return self._mono

    def skew_ms(self) -> int:
        return self._skew_ms

    def source_id(self) -> str:
        return "fixed"

    def advance_ms(self, delta: int) -> None:
        if isinstance(delta, bool) or not isinstance(delta, int):
            raise ValueError("delta must be an int")
        if delta < 0:
            raise ClockMonotonicity("monotonic clock cannot go backward")
        self._wall += delta
        self._mono += delta

    def set_wall_ms(self, wall_ms: int) -> None:
        """Wall clock may jump (NTP). Monotonic may not."""
        if isinstance(wall_ms, bool) or not isinstance(wall_ms, int):
            raise ValueError("wall_ms must be an int")
        self._wall = wall_ms


class MonotonicGuard(Clock):
    """
    Wraps another clock. Raises if mono_ms() ever decreases.

    Use in production to catch the two ways a monotonic source can
    fail: (a) a buggy underlying implementation, (b) a suspended
    process whose monotonic clock was rewritten. Both are rare and
    both are silent without this guard.
    """

    __slots__ = ("_inner", "_last_mono", "_lock")

    def __init__(self, inner: Clock) -> None:
        self._inner = inner
        self._last_mono = -1
        self._lock = threading.Lock()

    def wall_ms(self) -> int:
        return self._inner.wall_ms()

    def mono_ms(self) -> int:
        now = self._inner.mono_ms()
        with self._lock:
            if now < self._last_mono:
                raise ClockMonotonicity(
                    f"mono went backward: {self._last_mono} -> {now}"
                )
            self._last_mono = now
        return now

    def skew_ms(self) -> int:
        return self._inner.skew_ms()

    def source_id(self) -> str:
        return self._inner.source_id()

    def is_trusted(self) -> bool:
        return self._inner.is_trusted()

    @property
    def last_mono_ms(self) -> int:
        """Most recent monotonic read. Useful for post-mortem diagnostics."""
        return self._last_mono


# ══════════════════════════════════════════════════════════════════════════
# Signed time beacon
#
# Wire format (canonical JSON):
#
#   {
#     "body": "<b64url canonical JSON of {t, iat, exp, source, nonce}>",
#     "sig":  "<b64url Ed25519 signature over BEACON_CTX || body_bytes>"
#   }
#
# The signature covers the exact body bytes. The caller does not supply
# t_ms, iat_ms, exp_ms, source, or nonce separately — they are derived
# from the verified body. There is no way to install a beacon whose
# fields disagree with the signature.
# ══════════════════════════════════════════════════════════════════════════

BEACON_CTX = b"aegis-time-beacon-v1"
BEACON_BODY_KEYS = frozenset({"t", "iat", "exp", "source", "nonce"})
MAX_BEACON_BYTES = 4096


def _canonical_encode(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _canonical_decode(raw: bytes) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClockBeaconInvalid(f"beacon is not JSON: {exc}") from None
    if not isinstance(obj, dict):
        raise ClockBeaconInvalid("beacon is not an object")
    if _canonical_encode(obj) != raw:
        raise ClockBeaconInvalid("beacon is not canonical")
    return obj


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(s: object) -> bytes:
    if not isinstance(s, str):
        raise ClockBeaconInvalid("base64 input must be str")
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        raise ClockBeaconInvalid("base64 decode failed") from None
    if _b64e(raw) != s:
        raise ClockBeaconInvalid("non-canonical base64")
    return raw


@dataclass(frozen=True, slots=True)
class TimeBeacon:
    """
    A signed assertion that wall time was `t_ms` at the moment the
    beacon was created.

    Fields are derived from the signed body. Do not construct directly
    for production use; use `parse_signed` which verifies the envelope
    first. `sign` is provided for the issuer side and tests.

    Invariants (enforced by `sign` and `parse_signed`):
      iat_ms <= t_ms <= exp_ms
      nonce and source are non-empty strings
    """

    t_ms:   int
    iat_ms: int
    exp_ms: int
    source: str
    nonce:  str

    @classmethod
    def sign(
        cls,
        *,
        t_ms: int,
        iat_ms: int,
        exp_ms: int,
        source: str,
        nonce: str,
        private_key: Ed25519PrivateKey,
    ) -> bytes:
        """Produce the signed envelope bytes.

        For the beacon issuer and for tests. The verifier never calls this.
        """
        for name, value in (("t_ms", t_ms), ("iat_ms", iat_ms), ("exp_ms", exp_ms)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an int")
        if not isinstance(source, str) or not source:
            raise ValueError("source must be a non-empty string")
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        if not (iat_ms <= t_ms <= exp_ms):
            raise ValueError("beacon timestamps must be ordered iat <= t <= exp")

        body = _canonical_encode({
            "t": t_ms, "iat": iat_ms, "exp": exp_ms,
            "source": source, "nonce": nonce,
        })
        sig = private_key.sign(BEACON_CTX + body)
        return _canonical_encode({"body": _b64e(body), "sig": _b64e(sig)})

    @classmethod
    def parse_signed(
        cls,
        raw: bytes,
        verifier: Ed25519PublicKey,
    ) -> "TimeBeacon":
        """Verify the envelope and derive every field from the signed body.

        Any tampering with the body invalidates the signature. Any
        disagreement between the caller and the body is impossible
        because the caller supplies only `raw`.
        """
        if not isinstance(raw, (bytes, bytearray)):
            raise ClockBeaconInvalid("beacon raw must be bytes")
        raw = bytes(raw)
        if len(raw) > MAX_BEACON_BYTES:
            raise ClockBeaconInvalid("beacon raw too large")

        doc = _canonical_decode(raw)
        if set(doc) != {"body", "sig"}:
            raise ClockBeaconInvalid("beacon envelope shape")
        body = _b64d(doc["body"])
        sig = _b64d(doc["sig"])
        if len(sig) != 64:
            raise ClockBeaconInvalid("beacon signature must be 64 bytes")

        try:
            verifier.verify(sig, BEACON_CTX + body)
        except InvalidSignature:
            raise ClockBeaconInvalid("bad beacon signature") from None

        fields = _canonical_decode(body)
        if set(fields) != BEACON_BODY_KEYS:
            raise ClockBeaconInvalid("beacon body shape")

        t_ms, iat_ms, exp_ms = fields["t"], fields["iat"], fields["exp"]
        source, nonce = fields["source"], fields["nonce"]
        for name, value in (("t", t_ms), ("iat", iat_ms), ("exp", exp_ms)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ClockBeaconInvalid(f"beacon.{name} must be an int")
        if not isinstance(source, str) or not source:
            raise ClockBeaconInvalid("beacon.source must be a non-empty string")
        if not isinstance(nonce, str) or not nonce:
            raise ClockBeaconInvalid("beacon.nonce must be a non-empty string")
        if not (iat_ms <= t_ms <= exp_ms):
            raise ClockBeaconInvalid("beacon timestamps not ordered")

        return cls(t_ms=t_ms, iat_ms=iat_ms, exp_ms=exp_ms,
                   source=source, nonce=nonce)


class BeaconClock(Clock):
    """
    A clock anchored to a signed external time beacon.

    Between beacon refreshes, wall time advances from the anchor
    using the local monotonic clock. This gives:

      - Trust:      the anchor came from a verified signer.
      - Drift bound: reported wall may drift up to `max_drift_ms`
                     from true wall time between refreshes.
      - Monotonic:  a refresh that would move wall time backward is
                     rejected. Captured old beacons cannot be replayed
                     to install an earlier time.
      - Fail-closed: when the beacon expires or the drift bound is
                     exceeded, wall_ms() raises. There is no silent
                     fallback to SystemClock.

    The constructor and `refresh` take the raw signed envelope bytes,
    not a `TimeBeacon`. Fields are derived from the verified body.
    """

    __slots__ = (
        "_verifier", "_skew_ms", "_max_drift_ms",
        "_anchor", "_anchor_mono_ms", "_lock", "_mono",
    )

    def __init__(
        self,
        *,
        beacon_verifier: Ed25519PublicKey,
        initial_beacon_raw: bytes,
        skew_ms: int = 1000,
        max_drift_ms: int = 60_000,
        mono_source: Optional[Clock] = None,
    ) -> None:
        if isinstance(skew_ms, bool) or not isinstance(skew_ms, int):
            raise ValueError("skew_ms must be an int")
        if skew_ms < 0:
            raise ValueError("skew_ms must be >= 0")
        if isinstance(max_drift_ms, bool) or not isinstance(max_drift_ms, int):
            raise ValueError("max_drift_ms must be an int")
        if max_drift_ms <= 0:
            raise ValueError("max_drift_ms must be > 0")

        self._verifier = beacon_verifier
        self._skew_ms = skew_ms
        self._max_drift_ms = max_drift_ms
        self._lock = threading.Lock()
        self._anchor: Optional[TimeBeacon] = None
        self._anchor_mono_ms = 0
        self._mono = MonotonicGuard(mono_source or SystemClock())

        self._install(initial_beacon_raw)

    # Public API

    def refresh(self, raw: bytes) -> None:
        """Install a fresh beacon. Caller supplies only the signed bytes."""
        self._install(raw)

    def wall_ms(self) -> int:
        with self._lock:
            anchor = self._anchor
            anchor_mono = self._anchor_mono_ms
            if anchor is None:
                raise ClockBeaconInvalid("no beacon installed")
            now_mono = self._mono.mono_ms()
            elapsed = now_mono - anchor_mono
            if elapsed < 0:
                raise ClockMonotonicity("monotonic clock went backward")
            if elapsed > self._max_drift_ms:
                raise ClockBeaconInvalid(
                    f"beacon stale: {elapsed}ms since anchor > "
                    f"{self._max_drift_ms}ms"
                )
            wall = anchor.t_ms + elapsed
            if wall > anchor.exp_ms + self._skew_ms:
                raise ClockBeaconInvalid("wall time beyond beacon expiry")
            return wall

    def mono_ms(self) -> int:
        return self._mono.mono_ms()

    def skew_ms(self) -> int:
        return self._skew_ms

    def source_id(self) -> str:
        with self._lock:
            anchor = self._anchor
        return anchor.source if anchor is not None else "beacon"

    def is_trusted(self) -> bool:
        return True

    # Internal

    def _install(self, raw: bytes) -> None:
        if not isinstance(raw, (bytes, bytearray)):
            raise ClockBeaconInvalid("beacon raw must be bytes")
        raw = bytes(raw)
        beacon = TimeBeacon.parse_signed(raw, self._verifier)

        anchor_mono = self._mono.mono_ms()

        with self._lock:
            prev = self._anchor
            if prev is not None and beacon.t_ms < prev.t_ms:
                raise ClockBeaconInvalid(
                    f"beacon rollback: {beacon.t_ms} < {prev.t_ms}"
                )
            self._anchor = beacon
            self._anchor_mono_ms = anchor_mono


# ══════════════════════════════════════════════════════════════════════════
# Comparison helpers
#
# Two families:
#   * within_skew / is_fresh  return bool — the caller picks the error model.
#   * require_within_skew / require_fresh  raise ClockSkew on violation.
# The GovernorEngine enrollment path uses require_within_skew to mirror
# TokenIssuer's enrollment_max_skew check while raising a clock-layer
# exception rather than a capchain Reject.
# ══════════════════════════════════════════════════════════════════════════

def within_skew(a_ms: int, b_ms: int, tolerance_ms: int) -> bool:
    """
    True if two wall timestamps are within tolerance.

    Use whenever comparing timestamps from different machines or
    different clocks. A caller with two clocks should pass
    ``clock_a.skew_ms() + clock_b.skew_ms()`` as ``tolerance_ms``;
    the same clock needs only ``2 * clock.skew_ms()`` (NTP jump in
    both directions).
    """
    if isinstance(tolerance_ms, bool) or not isinstance(tolerance_ms, int):
        raise ValueError("tolerance_ms must be an int")
    if tolerance_ms < 0:
        raise ValueError("tolerance_ms must be >= 0")
    return abs(int(a_ms) - int(b_ms)) <= tolerance_ms


def require_within_skew(
    a_ms: int,
    b_ms: int,
    tolerance_ms: int,
    *,
    what: str = "timestamp",
) -> None:
    """
    Raise `ClockSkew` if two timestamps differ by more than tolerance.

    Mirrors TokenIssuer's enrollment_max_skew check for callers that
    want a clock-layer exception instead of capchain.Reject. The
    GovernorEngine enrollment path uses this before delegating to
    capchain, so a skew violation becomes `ClockSkew` at the boundary.
    """
    if isinstance(tolerance_ms, bool) or not isinstance(tolerance_ms, int):
        raise ValueError("tolerance_ms must be an int")
    if tolerance_ms < 0:
        raise ValueError("tolerance_ms must be >= 0")
    delta = abs(int(a_ms) - int(b_ms))
    if delta > tolerance_ms:
        raise ClockSkew(
            f"{what}: skew {delta}ms exceeds tolerance {tolerance_ms}ms"
        )


def is_fresh(
    *,
    observed_ms: int,
    now_ms: int,
    window_ms: int,
    future_skew_ms: int = 0,
) -> bool:
    """
    True if observed_ms is within window_ms behind now_ms, allowing up
    to future_skew_ms ahead (the caller's declared clock skew).

    Rejects timestamps further in the future than future_skew_ms — a
    signed payload from the future is either a bug or an attack, never
    a valid observation.

    Callers with a declared skew pass `future_skew_ms=clock.skew_ms()`.
    Callers without pass 0 (the default), which enforces "observed must
    not be in the future at all".
    """
    if isinstance(window_ms, bool) or not isinstance(window_ms, int):
        raise ValueError("window_ms must be an int")
    if window_ms < 0:
        raise ValueError("window_ms must be >= 0")
    if isinstance(future_skew_ms, bool) or not isinstance(future_skew_ms, int):
        raise ValueError("future_skew_ms must be an int")
    if future_skew_ms < 0:
        raise ValueError("future_skew_ms must be >= 0")

    age = int(now_ms) - int(observed_ms)
    return -future_skew_ms <= age <= window_ms


def require_fresh(
    *,
    observed_ms: int,
    now_ms: int,
    window_ms: int,
    future_skew_ms: int = 0,
    what: str = "timestamp",
) -> None:
    """
    Raise `ClockSkew` if `is_fresh` would return False.

    Same semantics as `is_fresh`; the caller chooses exception vs bool.
    """
    if not is_fresh(
        observed_ms=observed_ms,
        now_ms=now_ms,
        window_ms=window_ms,
        future_skew_ms=future_skew_ms,
    ):
        age = int(now_ms) - int(observed_ms)
        raise ClockSkew(
            f"{what}: age {age}ms outside window "
            f"[-{future_skew_ms}, {window_ms}]ms"
        )


def expires_at(wall_ms: int, ttl_ms: int) -> int:
    """Absolute expiry from a wall time and a non-negative TTL."""
    if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, int):
        raise ValueError("ttl_ms must be an int")
    if ttl_ms < 0:
        raise ValueError("ttl_ms must be >= 0")
    return int(wall_ms) + ttl_ms



class ClockHolder:
    """
    A process-local holder. Not a global singleton.

    Every Runtime / AgentOS / agent gets its own holder and passes
    it in. Why not a module-level singleton:

      - Tests need to inject FixedClock.
      - Different agents may use different trust models.
      - A shared clock is a shared failure domain.

    Why not thread the Clock through every call:

      - Too noisy. The holder is the one place the current Clock
        is resolved; everything else asks the holder.
    """

    __slots__ = ("_clock",)

    def __init__(self, clock: Optional[Clock] = None) -> None:
        self._clock = clock or SystemClock()

    @property
    def clock(self) -> Clock:
        return self._clock

    def set(self, clock: Clock) -> None:
        """Swap the clock. For tests and beacon refresh."""
        self._clock = clock

    # Short-form accessors so call sites stay readable.

    def wall_ms(self) -> int:
        return self._clock.wall_ms()

    def mono_ms(self) -> int:
        return self._clock.mono_ms()

    def wall_s(self) -> int:
        return self._clock.wall_s()

    def mono_s(self) -> int:
        return self._clock.mono_s()

    def now_seconds(self) -> int:
        return self._clock.now_seconds()

    def skew_ms(self) -> int:
        return self._clock.skew_ms()

    def __call__(self) -> int:
        return self._clock.now_seconds()