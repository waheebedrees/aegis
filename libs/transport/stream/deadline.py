"""Absolute, propagating deadlines. Nothing waits unbounded by accident."""

from __future__ import annotations

import asyncio
import contextvars
import time
from typing import TypeVar, Generator, Optional, Awaitable
from contextlib import contextmanager
import math
from libs.transport.stream.errors import (
    DeadlineExceeded,
    Scope,
    StreamError,
    Status,
)

T = TypeVar("T")

MAX_TIMEOUT_S = 24 * 3600.0


def _validate(seconds: object, op: str) -> float:
    if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0:
        raise StreamError(Status.INVALID_ARGUMENT, "BAD_TIMEOUT", op, scope=Scope.CALLER)
    if seconds > MAX_TIMEOUT_S:
        raise StreamError(Status.OUT_OF_RANGE, "TIMEOUT_TOO_LARGE", op, scope=Scope.CALLER)
    return float(seconds)


class Deadline:
    __slots__ = ("_at",)

    def __init__(self, at: float) -> None:
        self._at = float(at)

    @classmethod
    def after(cls, seconds: float, *, op: str = "deadline") -> "Deadline":
        return cls(asyncio.get_running_loop().time() + _validate(seconds, op))

    @classmethod
    def unbounded(cls) -> "Deadline":
        """Explicit opt-out. Use only for long-lived accept loops."""
        return cls(math.inf)

    @property
    def at(self) -> float:
        return self._at

    @property
    def is_unbounded(self) -> bool:
        return math.isinf(self._at)

    def remaining(self) -> float:
        return math.inf if self.is_unbounded else self._at - asyncio.get_running_loop().time()

    @property
    def expired(self) -> bool:
        return self.remaining() <= 0

    def min(self, other: Optional["Deadline"]) -> "Deadline":
        return self if other is None or self._at <= other._at else other

    def check(self, op: str, *, scope: Scope = Scope.CALLER) -> None:
        if self.expired:
            raise DeadlineExceeded(op, scope=scope)

    async def run(self, aw: Awaitable[T], op: str, *, scope: Scope = Scope.CALLER) -> T:
        rem = self.min(_ambient.get()).remaining()
        if rem <= 0:
            raise DeadlineExceeded(op, scope=scope)
        if math.isinf(rem):
            return await aw
        try:
            return await asyncio.wait_for(aw, rem)
        except asyncio.TimeoutError:
            raise DeadlineExceeded(op, scope=scope) from None

    def __repr__(self) -> str:
        return f"<Deadline remaining={self.remaining():.3f}s>"


_ambient: contextvars.ContextVar[Optional[Deadline]] = contextvars.ContextVar(
    "aegis_deadline", default=None
)


def ambient_deadline() -> Optional[Deadline]:
    return _ambient.get()


@contextmanager
def deadline_scope(deadline: Deadline) -> Generator[Deadline]:
    """Everything awaited inside inherits (and is clamped by) this deadline."""
    merged = deadline.min(_ambient.get())
    token = _ambient.set(merged)
    try:
        yield merged
    finally:
        _ambient.reset(token)


def effective_deadline(
    deadline: Optional[Deadline],
    timeout: Optional[float],
    *,
    default: float,
    op: str,
) -> Deadline:
    """Resolve caller args to one Deadline. Precedence: explicit > default;
    the ambient scope always clamps. Never returns None."""
    if deadline is not None and timeout is not None:
        raise StreamError(
            Status.INVALID_ARGUMENT,
            "DEADLINE_AND_TIMEOUT",
            op,
            scope=Scope.CALLER,
        )
    if deadline is not None:
        if not isinstance(deadline, Deadline):
            raise StreamError(Status.INVALID_ARGUMENT, "BAD_DEADLINE", op, scope=Scope.CALLER)
        d = deadline
    elif timeout is not None:
        d = Deadline.after(timeout, op=op)
    else:
        d = Deadline.after(default, op=op)
    return d.min(_ambient.get())
