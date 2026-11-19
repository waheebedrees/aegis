"""libs/proto/server.py — dispatch accepted streams to registered services.

One Server can serve many Transports. Admission is refuse-never-queue:
unknown kind, overload, and shutdown are answered with a synchronous CANCEL
(status-vocabulary reason) from the accept loop, which therefore never awaits
a peer-controlled write.

Bounds:  live calls <= max_call_concurrency (across all transports)
         per call   <= ChannelConfig (+ per-method max_message_bytes)
         per call   time <= min(client deadline, max_call_seconds) + linger
"""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass, field

import re

import time
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterable, Mapping, Optional, Sequence
from libs.transport.stream_session import Stream, StreamError, Transport
from libs.proto.status import   error, Status
from libs.proto import (
    Channel, 
    ChannelError, 
    ChannelConfig, 
    ChannelHello,  
    Mode, 
    TLVEntry,
    Message,
    JSON, 
    DEFAULT_MAX_MESSAGE_BYTES
)

log = logging.getLogger(__name__)


Validator = Callable[[Any], Any]     # returns the (possibly converted) value; raise to reject
Handler = Callable[["ServerCall"], Awaitable[Any]]
Next = Callable[["ServerCall"], Awaitable[Any]]
Interceptor = Callable[["ServerCall", Next], Awaitable[Any]]

RESERVED_NS = "aegis."
_KIND_RE = re.compile(r"[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+/v[1-9][0-9]{0,5}")
_METHOD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)?")


def _printable(s: object, limit: int) -> bool:
    return isinstance(s, str) and 1 <= len(s) <= limit and all(" " < c <= "~" for c in s)


@dataclass(frozen=True, slots=True)
class MethodDef:
    name: str
    mode: Mode
    handler: Handler
    validate_request: Optional[Validator] = None
    validate_response: Optional[Validator] = None
    max_message_bytes: Optional[int] = None
    requires_capability: Optional[str] = None     # enforced by an interceptor (M4)
    idempotent: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or len(self.name) > 128 or not _METHOD_RE.fullmatch(self.name):
            raise ValueError(f"invalid method name {self.name!r}")
        if not isinstance(self.mode, Mode):
            raise TypeError("mode must be a Mode")
        if not callable(self.handler):
            raise TypeError("handler must be callable")
        for v in (self.validate_request, self.validate_response):
            if v is not None and not callable(v):
                raise TypeError("validators must be callable")
        if self.max_message_bytes is not None and (
                type(self.max_message_bytes) is not int
                or not 1 <= self.max_message_bytes <= DEFAULT_MAX_MESSAGE_BYTES):
            raise ValueError("max_message_bytes out of range")
        if self.requires_capability is not None and not _printable(self.requires_capability, 128):
            raise ValueError("requires_capability must be printable ASCII <= 128")
        if type(self.idempotent) is not bool:
            raise TypeError("idempotent must be bool")



@dataclass(frozen=True, slots=True)
class ServiceDef:
    kind: str
    methods: Mapping[str, MethodDef]
    content_types: tuple[str, ...] = (JSON,)
    features: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or len(self.kind) > 64 or not _KIND_RE.fullmatch(self.kind):
            raise ValueError(f"invalid kind {self.kind!r} (want ns.svc/vN)")
        table = dict(self.methods)
        for name, m in table.items():
            if not isinstance(m, MethodDef) or m.name != name:
                raise ValueError(f"method table mismatch at {name!r}")
        if not table:
            raise ValueError("a service needs at least one method")
        object.__setattr__(self, "methods", MappingProxyType(table))
        if (not isinstance(self.content_types, tuple) or not self.content_types
                or len(set(self.content_types)) != len(self.content_types)):
            raise ValueError("content_types must be a non-empty tuple without duplicates")
        if not isinstance(self.features, frozenset) or len(self.features) > 64 or \
                not all(_printable(f, 64) for f in self.features):
            raise ValueError("features must be <= 64 printable strings")



@dataclass
class ServerCall:
    channel: Channel
    hello: ChannelHello
    method_def: MethodDef
    peer_id: str
    deadline: Optional[float]        # monotonic seconds, None = no deadline
    received_at: float               # wall clock
    response_headers: dict[int, bytes] = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return self.channel.kind

    @property
    def method(self) -> str:
        return self.method_def.name

    async def recv(self, *, timeout: Optional[float] = None) -> Optional[Message]:
        self.check_deadline()
        return await self.channel.recv(timeout=timeout)

    async def send(self, value: Any, *, headers: tuple[TLVEntry, ...] = ()) -> None:
        self.check_deadline()
        await self.channel.send(value, headers=headers)

    async def end(self, status: Status = Status.OK, message: str = "") -> None:
        await self.channel.end(status, message)

    async def fail(self, status: Status, message: str = "") -> None:
        await self.channel.end(status, message)

    def remaining_s(self) -> Optional[float]:
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.monotonic())

    def check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise error(Status.DEADLINE_EXCEEDED, "channel deadline")




def build_chain(interceptors: Iterable[Interceptor]):

    async def _invoke_handler(call: ServerCall) -> Any:
        return await call.method_def.handler(call)
    def _link(ic: Interceptor, nxt: Next) -> Next:
        async def run(call: ServerCall) -> Any:
            return await ic(call, nxt)
        return run
    chain: Next = _invoke_handler
    for ic in reversed(tuple(interceptors)):
        if not callable(ic):
            raise TypeError("interceptors must be callable")
        chain = _link(ic, chain)
    return chain



@dataclass(frozen=True, slots=True)
class ServerConfig:
    channel: ChannelConfig = ChannelConfig()
    max_call_concurrency: int = 256
    max_call_seconds: float = 300.0
    linger: float = 5.0
    shutdown_grace: float = 5.0

    def __post_init__(self) -> None:
        if not isinstance(self.channel, ChannelConfig):
            raise TypeError("channel must be a ChannelConfig")
        if type(self.max_call_concurrency) is not int or not 1 <= self.max_call_concurrency <= 65536:
            raise ValueError("max_call_concurrency out of range")
        for n in ("max_call_seconds", "linger", "shutdown_grace"):
            v = getattr(self, n)
            if type(v) not in (int, float) or not math.isfinite(v) or v <= 0:
                raise ValueError(f"{n} must be a positive finite number")


class Server:
    pass 
