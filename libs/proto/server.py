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
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Coroutine,
)
from libs.transport.stream_session import Stream, StreamError, Transport
from libs.proto.status import error, Status, ProtocolError
from libs.proto.codec import DEFAULT_CODECS, OCTET_STREAM, CodecRegistry, Codec
from libs.proto import (
    Channel,
    ChannelError,
    ChannelConfig,
    ChannelHello,
    Mode,
    TLVEntry,
    DEFAULT_CODECS,
    Message,
    JSON,
    DEFAULT_MAX_MESSAGE_BYTES,
)

from libs.proto.hello import HELLO_REGISTRY
from libs.proto.envelope import MESSAGE_REGISTRY

log = logging.getLogger(__name__)


Validator = Callable[[Any], Any]  # returns the (possibly converted) value; raise to reject
Handler = Callable[["ServerCall"], Awaitable[Any]]
Next = Callable[["ServerCall"], Awaitable[Any]]
Interceptor = Callable[["ServerCall", Next], Awaitable[Any]]

RESERVED_NS = "aegis."
_KIND_RE = re.compile(r"[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+/v[1-9][0-9]{0,5}")
_METHOD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)?")

_MAX_DETAIL = 2048


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
    requires_capability: Optional[str] = None  # enforced by an interceptor (M4)
    idempotent: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or len(self.name) > 128
            or not _METHOD_RE.fullmatch(self.name)
        ):
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
            or not 1 <= self.max_message_bytes <= DEFAULT_MAX_MESSAGE_BYTES
        ):
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

    def require_method(self, name: str) -> MethodDef:
        spec = self.methods.get(name)
        if spec is None:
            raise ProtocolError(Status.NOT_FOUND, f"unknown method {name!r}")
        return spec

    def __post_init__(self) -> None:
        if (
            not isinstance(self.kind, str)
            or len(self.kind) > 64
            or not _KIND_RE.fullmatch(self.kind)
        ):
            raise ValueError(f"invalid kind {self.kind!r} (want ns.svc/vN)")
        table = dict(self.methods)
        for name, m in table.items():
            if not isinstance(m, MethodDef) or m.name != name:
                raise ValueError(f"method table mismatch at {name!r}")
        if not table:
            raise ValueError("a service needs at least one method")
        object.__setattr__(self, "methods", MappingProxyType(table))
        if (
            not isinstance(self.content_types, tuple)
            or not self.content_types
            or len(set(self.content_types)) != len(self.content_types)
        ):
            raise ValueError("content_types must be a non-empty tuple without duplicates")
        if (
            not isinstance(self.features, frozenset)
            or len(self.features) > 64
            or not all(_printable(f, 64) for f in self.features)
        ):
            raise ValueError("features must be <= 64 printable strings")


def build_service(obj: object) -> ServiceDef:
    spec = getattr(type(obj), "__aegis_service__", None)
    if spec is None:
        raise TypeError(f"{type(obj).__name__} is not a @service class")
    kind, cts, features = spec
    methods: dict[str, MethodDef] = {}
    for attr in dir(type(obj)):
        meta = getattr(getattr(type(obj), attr, None), "__aegis_method__", None)
        if meta is None:
            continue
        name, mode, opts = meta
        if name in methods:
            raise ValueError(f"duplicate method {name!r} in {kind}")
        methods[name] = MethodDef(name, mode, getattr(obj, attr), **opts)
    return ServiceDef(kind, methods, cts, features)


class ServiceRegistry:
    __slots__ = ("_svcs", "_frozen")

    def __init__(self, services: Iterable[object] = ()) -> None:
        self._svcs: dict[str, ServiceDef] = {}
        self._frozen = False
        for s in services:
            self.register(s)

    def register(self, svc: object, *, core: bool = False) -> ServiceDef:
        """Accepts a ServiceDef or an instance of a @service-decorated class."""
        if self._frozen:
            raise RuntimeError("ServiceRegistry is frozen")
        sd = svc if isinstance(svc, ServiceDef) else build_service(svc)
        if sd.kind.startswith(RESERVED_NS) and not core:
            raise ValueError(f"{RESERVED_NS}* is reserved for core services")
        if sd.kind in self._svcs:
            raise ValueError(f"duplicate service {sd.kind}")
        self._svcs[sd.kind] = sd
        return sd

    def freeze(self) -> "ServiceRegistry":
        self._frozen = True
        return self

    def get(self, kind: str) -> Optional[ServiceDef]:
        return self._svcs.get(kind)

    def __iter__(self):
        return iter(self._svcs.values())

    def catalog(self) -> dict:
        """Deterministic, codec-friendly description (served by aegis.meta in M3)."""
        return {
            sd.kind: {
                "content_types": list(sd.content_types),
                "features": sorted(sd.features),
                "methods": {
                    m.name: {"mode": m.mode.name, "idempotent": m.idempotent}
                    for m in sorted(sd.methods.values(), key=lambda m: m.name)
                },
            }
            for sd in sorted(self._svcs.values(), key=lambda s: s.kind)
        }


class _CallBase:
    __slots__ = ("_ch", "_codec")

    def __init__(self, ch: Channel, codec: Codec) -> None:
        self._ch = ch
        self._codec = codec

    @property
    def channel(self) -> Channel:
        return self._ch

    @property
    def peer_id(self) -> str:
        return self._ch.peer_id

    @property
    def kind(self) -> str:
        return self._ch.kind

    @property
    def method(self) -> str:
        return self._ch.hello.method

    @property
    def hello(self) -> ChannelHello:
        return self._ch.hello

    @property
    def mode(self) -> Mode:
        return self._ch.mode

    @property
    def remaining(self) -> Optional[float]:
        return self._ch.remaining_s()

    def ext(self, tag: int) -> Optional[bytes]:
        for e in self._ch.hello.extensions:
            if e.tag == tag:
                return e.value
        return None

    def _encode_detail(self, detail: Any) -> bytes:
        if detail is None:
            return b""
        raw = detail if type(detail) is bytes else self._codec.encode(detail)
        return raw if len(raw) <= _MAX_DETAIL else b""  # never truncate structure

    async def end(self, *, message: str = "", trailers: tuple[TLVEntry, ...] = ()) -> None:
        await self._ch.end(message=message, trailers=trailers)

    def cancel(self, reason: str = "cancelled") -> None:
        self._ch.cancel(reason)


class ServerCall(_CallBase):
    __slots__ = (
        "service",
        "method_def",
        "context",
        "open_token",
        "open_pop",
        "received_at",
    )

    def __init__(
        self,
        ch: Channel,
        codec: Codec,
        service: ServiceDef,
        method_def: MethodDef,
        *,
        open_token: bytes,
        open_pop: bytes,
    ) -> None:
        super().__init__(ch, codec)
        self.service = service
        self.method_def = method_def
        self.context: dict[str, Any] = {}  # interceptor scratch space
        self.open_token = open_token
        self.open_pop = open_pop
        self.received_at = (time.monotonic(),)

    @property
    def remaining(self) -> Optional[float]:
        return self.channel.remaining_s()

    @property
    def peer_id(self) -> str:
        return self.channel.peer_id

    @property
    def deadline(self) -> Optional[float]:
        return self.channel.deadline

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
    max_served_sessions: int = 32
    deadline_ms: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.channel, ChannelConfig):
            raise TypeError("channel must be a ChannelConfig")
        if (
            type(self.max_call_concurrency) is not int
            or not 1 <= self.max_call_concurrency <= 65536
        ):
            raise ValueError("max_call_concurrency out of range")
        for n in ("max_call_seconds", "linger", "shutdown_grace"):
            v = getattr(self, n)
            if type(v) not in (int, float) or not math.isfinite(v) or v <= 0:
                raise ValueError(f"{n} must be a positive finite number")


@dataclass(frozen=True, slots=True)
class CapchainCerdi:
    """Created after TlsConnection.wrap() AND Transport.establish()."""

    token: bytes = b""
    pop: bytes = b""


@dataclass(frozen=True, slots=True)
class VerifiedSession:
    """Created after TlsConnection.wrap() AND Transport.establish()."""

    transport: Transport
    Stream: Stream
    accepts: bool

    @property
    def channel_binding(self):
        self.transport.channel_binding

    @property
    def peer_id(self):
        self.transport.peer_id

    def __post_init__(self) -> None:
        if self.transport.peer_id != self.peer_id:
            raise ValueError("TLS identity and transport identity differ")
        if self.channel_binding and len(self.channel_binding) != 32:
            raise ValueError("invalid channel binding")
        if type(self.accepts) is not bool:
            raise ValueError("accepts must be bool")


# Reset-reason vocabulary (frozen): a channel-level CANCEL carries
# status.name.lower(). The transport prefixes it ("local:"/"peer:"), so the
# receiver maps the last ':'-separated token back to a Status.
def status_to_reason(status: Status) -> str:
    return status.name.lower()


def _cancel_with_status(stream: Stream, status: Status, message: str = "") -> None:
    safe = "".join(c if " " <= c <= "~" else "_" for c in message)[:64]
    stream.cancel(f"status:{int(status)}:{safe}")


def sanitize(text: object, limit: int = 256) -> str:
    return "".join(c if " " <= c <= "~" else "_" for c in str(text)[:limit])


class Server:
    __slots__ = (
        "_services",
        "_codecs",
        "_headers",
        "_cfg",
        "_chain",
        "_live",
        "_closing",
        "_hello_headers",
        "_message_headers",
    )

    def __init__(
        self,
        services: ServiceRegistry,
        codecs: CodecRegistry = DEFAULT_CODECS,
        interceptors: Iterable[Interceptor] = (),
        config: ServerConfig = ServerConfig(),
        hello_headers=HELLO_REGISTRY,
        message_headers=MESSAGE_REGISTRY,
    ) -> None:

        self._services = services.freeze()
        self._codecs = codecs.freeze()
        self._cfg = config

        for sd in self._services:  # fail at construction, not per call
            missing = [ct for ct in sd.content_types if ct not in self._codecs]
            if missing:
                raise ValueError(f"{sd.kind}: no codec for {missing}")

        self._chain = build_chain(interceptors)
        self._live: set[asyncio.Task] = set()
        self._closing = False
        self._hello_headers = hello_headers
        self._message_headers = message_headers

    async def serve(self, session: VerifiedSession) -> None:
        """Dispatch streams from one connection until it closes."""
        if not session.accepts:
            raise ValueError("session is not an accepting endpoint")
        transport = session.transport
        if transport in self._live or len(self._live) >= self._cfg.max_served_sessions:
            raise error(Status.RESOURCE_EXHAUSTED, "serve limit")

        while True:
            try:
                st = await transport.accept()
            except StreamError:
                return
            if self._closing:
                st.cancel(status_to_reason(Status.UNAVAILABLE))
                return
            svc = self._services.get(st.kind)
            if svc is None:
                st.cancel(status_to_reason(Status.UNIMPLEMENTED))
                return
            if len(self._live) >= self._cfg.max_call_concurrency:
                st.cancel(status_to_reason(Status.RESOURCE_EXHAUSTED))
                return
            task = asyncio.get_running_loop().create_task(self._run(svc, st))
            self._live.add(task)
            task.add_done_callback(self._live.discard)

    async def _invoke(self, call: ServerCall) -> Any:
        rem = call.remaining
        budget = self._cfg.max_call_seconds if rem is None else min(rem, self._cfg.max_call_seconds)
        scope = asyncio.timeout(budget)
        try:
            async with scope:
                return await self._chain(call)
        except TimeoutError:
            if scope.expired():
                raise ChannelError(Status.DEADLINE_EXCEEDED, "deadline") from None
            raise

    async def _run(self, svc: ServiceDef, st: Stream) -> None:

        # 1. Decode hello.
        try:
            hello = ChannelHello.decode(st.open_payload)
        except ProtocolError as exc:
            try:
                st.cancel(status_to_reason(exc.status))
            except Exception:
                pass
            return

        # 2. Resolve method.
        try:
            m = svc.require_method(hello.method)
        except ProtocolError:
            _cancel_with_status(st, Status.NOT_FOUND, f"unknown method {hello.method!r}"[:80])
            return

        if hello.mode is not m.mode:
            _cancel_with_status(
                st,
                Status.FAILED_PRECONDITION,
                f"expected {m.mode.name}, got {hello.mode.name}",
            )
            return

        try:
            codec = self._codecs.require(hello.content_type)
        except ProtocolError:
            _cancel_with_status(st, Status.UNSUPPORTED_MEDIA, "codec")
            return

        deadline_at: Optional[float] = None
        if hello.deadline_ms:
            declared = hello.deadline_ms / 1000.0
            if declared > self._cfg.deadline_ms:
                _cancel_with_status(st, Status.INVALID_ARGUMENT, "deadline too long")
                return
            deadline_at = st.opened_at + declared

        # 6. Build channel + context.
        ch = Channel(
            st,
            hello,
            codec,
            role="acceptor",
            config=self._cfg.channel,
            deadline_at=deadline_at,
        )
        try:
            await self._dispatch(svc, m, ch, st)
        except asyncio.CancelledError:
            ch.cancel(status_to_reason(Status.UNAVAILABLE))
            raise
        except BaseException:
            log.exception("dispatch crashed kind=%s", sanitize(st.kind, 64))
            ch.cancel(status_to_reason(Status.INTERNAL))
            raise

    async def _complete(self, call: ServerCall, result: Any) -> None:
        ch = call.channel
        if ch.send_closed:
            if result is not None:
                log.warning(
                    "handler returned a value after ending kind=%s method=%s",
                    sanitize(call.kind, 64),
                    sanitize(call.method, 128),
                )
            return
        try:
            if result is not None:
                await call.send(result)
            await call.end()
        except ChannelError as exc:
            if exc.status is Status.FAILED_PRECONDITION:
                raise ChannelError(
                    Status.INTERNAL,
                    f"handler produced an invalid response sequence for {call.method}",
                ) from None
            raise

    async def _reject(
        self,
        ch: Channel,
        status: Status,
        message: str = "",
        *,
        retry_after_ms: int = 0,
        detail: bytes = b"",
    ) -> None:
        try:
            await ch.fail(
                status,
                sanitize(message, 256),
                retry_after_ms=min(max(int(retry_after_ms), 0), 0xFFFFFFFF),
                detail=detail if len(detail) <= 2048 else b"",
            )
        except ChannelError:
            ch.cancel(status_to_reason(status))

    async def _reject_after_hello(
        self, stream: Stream, hello: ChannelHello, status: Status, detail: str
    ):
        try:
            ch = Channel(
                stream,
                hello,
                role="acceptor",
                config=self._cfg.channel,
                codec=self._codecs.get(hello.content_type),
            )
            await ch.fail(status, detail)
            await ch.aclose()  # <-- drains the client's pending DATA+END, then closes
        except Exception:
            try:
                stream.cancel(f"reject:{status.name.lower()}"[:64])
            except Exception:
                pass

    async def _dispatch(
        self, svc: ServiceDef, m: Optional[MethodDef], ch: Channel, st: Stream
    ) -> None:
        pass
        hello = ch.hello
        if m is None:
            return await self._reject(
                ch,
                Status.UNIMPLEMENTED,
                f"method {sanitize(hello.method, 128)}",
            )
        if hello.mode is not m.mode:
            return await self._reject(
                ch,
                Status.INVALID_ARGUMENT,
                f"mode {hello.mode.name} != {m.mode.name}",
            )
        ct = hello.content_type or OCTET_STREAM
        if ct not in svc.content_types:
            return await self._reject(ch, Status.UNSUPPORTED_MEDIA, ",".join(svc.content_types))

        call = ServerCall(
            ch,
            self._codecs.get(ct),
            svc,
            m,
            open_token=st.open_token,
            open_pop=st.open_pop,
        )
        try:
            result = await self._invoke(call)
            await self._complete(call, result)
        except ChannelError as exc:
            await self._reject(
                ch,
                exc.status,
                exc.message,
                retry_after_ms=exc.retry_after_ms,
                detail=exc.detail,
            )

        except Exception:
            log.exception(
                "handler failed kind=%s method=%s peer=%s",
                sanitize(call.kind, 64),
                sanitize(call.method, 128),
                sanitize(call.peer_id),
            )
            await self._reject(ch, Status.INTERNAL, "internal error")
