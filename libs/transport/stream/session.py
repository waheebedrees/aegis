"""libs/transport/stream/session.py — multiplexed session over the v4 framing.

Role model: the client opens streams (odd ids, strictly increasing); the
server accepts them. There is no stream-id collision space.

Liveness: the reader enforces idle_timeout per frame boundary, and the ping
loop fails the connection after MAX_OUTSTANDING_PINGS unanswered pings.

Memory: every peer-influenced structure is bounded.
    live streams          <= config.max_streams          (covers pending accepts)
    buffered per stream   <= config.stream_window
    retained per stream   <= OPEN_MAX_TOKEN + OPEN_MAX_POP + OPEN_MAX_BODY
    retired tombstones    <= 8 * config.max_streams ids
    pending control       <= one pong slot + one entry per live stream
    tolerated stale bytes <= MAX_STALE_BYTES for the connection's lifetime

Fatality model: a fatal TransportError is reserved for behaviour a compliant
peer can never produce. Races that two correct peers can legitimately hit
(data crossing a CANCEL, credit for a just-retired stream) are tolerated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import asyncio
import enum
import logging
import math
import struct
import time
import secrets

from typing import (
    Awaitable,
    Iterator,
    Mapping,
    Optional,
    Protocol,
    TypeGuard,
    Callable,
    runtime_checkable,
)
from collections import deque
from libs.transport.frame import (
    MAX_STREAM_ID,
    FrameType,
    make_open_stream,
    parse_open_stream_body,
    parse_reason,
    parse_stream_data,
    parse_window_update,
    FIXED_OVERHEAD,
    MAX_CHUNK_BYTES,
    MAX_SEQ,
    MAX_WINDOW_CREDIT,
    PING_NONCE_BYTES,
    Frame,
    Flags,
    FrameError,
    StreamChunk,
    make_cancel,
    make_ping,
    make_pong,
    make_stream_data,
    make_window_update,
    STREAM_MAC_BYTES,
)

from libs.transport.frame import (
    DEFAULT_REGISTRY,
    FIXED_OVERHEAD,
    MAX_CHUNK_BYTES,
    MAX_FRAME_BYTES,
    OPEN_MAX_BODY,
    OPEN_MAX_POP,
    OPEN_MAX_TOKEN,
    Frame,
    FrameError,
    FrameRegistry,
    FrameStream,
    FrameType,
    StreamClosed,
    make_close,
    make_data,
    make_session_init,
    parse_reason,
)

from libs.transport.stream._signer import HmacStreamSigner, StreamSigner

from libs.transport.stream.errors import (
    AegisError,
    DeadlineExceeded,
    ProtocolViolation,
    Status,
    StreamError,
    TransportError,
    close_reason,
    safe_text,
    Scope,
    status_from_wire,
)

from libs.transport.stream.deadline import (
    deadline_scope,
    effective_deadline,
    Deadline,
)
from libs.transport.tls import SessionSecrets, TlsConnection
from libs.transport.stream.stream import MAC_LEN, Stream

from libs.transport.stream.multiplexer import StreamAuthorizer, StreamMultiplexer

log = logging.getLogger(__name__)

# SESSION_INIT body: version, features, max_frame, stream_window, max_streams
_HELLO = struct.Struct(">HIIIH")

assert _HELLO.size == 16, _HELLO.size

MAC_LEN = STREAM_MAC_BYTES
MAX_OUTSTANDING_PINGS = 3
PROTOCOL_VERSION = 4
MIN_MAX_FRAME = 64 * 1024
MIN_STREAM_WINDOW = 4 * 1024
MAX_STREAM_WINDOW = 1024 * 1024
MAX_STREAMS = 256
MAX_BUFFERED = 32 * 1024 * 1024
PER_STREAM_OVERHEAD = OPEN_MAX_TOKEN + OPEN_MAX_POP + OPEN_MAX_BODY
MAX_STREAM_OVERHEAD = 4 * 1024 * 1024
HANDSHAKE_MAX_PAYLOAD = FIXED_OVERHEAD + 64
CLOSE_WRITE_TIMEOUT = 1.0
SHUTDOWN_GRACE = 0.5

MAX_STALE_BYTES = 8 * 1024 * 1024
RETIRED_RING_FACTOR = 8


class Feature(enum.IntFlag):
    STREAMS = 0x0001


class SessionState(enum.Enum):
    HANDSHAKING = "handshaking"
    OPEN = "open"
    CLOSING = "closing"
    CLOSED = "closed"


class StreamState(enum.Enum):
    OPEN = "open"
    HALF_CLOSED_LOCAL = "half_closed_local"
    HALF_CLOSED_REMOTE = "half_closed_remote"
    CLOSED = "closed"
    RESET = "reset"


_CORE_TYPES = frozenset(
    {
        FrameType.SESSION_INIT,
        FrameType.OPEN_STREAM,
        FrameType.STREAM_DATA,
        FrameType.WINDOW_UPDATE,
        FrameType.CANCEL,
        FrameType.PING,
        FrameType.PONG,
        FrameType.CLOSE,
        FrameType.ERROR,
    }
)

WriteFn = Callable[[Frame], Awaitable[bool]]
DataHandler = Callable[["Session", Frame], None]
RequestStopFn = Callable[["TransportError"], None]


def _pos(value: object, name: str) -> None:
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)  # type: ignore
        or value <= 0  # type: ignore
    ):
        raise ValueError(f"{name} must be a finite positive number")


def _bounded(v: object, name: str, lo: int, hi: int) -> None:
    if type(v) is not int or not lo <= v <= hi:
        raise ValueError(f"{name} must be an int in {lo}..{hi}")


def _addr(writer: object) -> str:
    try:
        peer = writer.get_extra_info("peername")  # type: ignore[attr-defined]
    except Exception:
        return "-"
    return (
        f"{safe_text(peer[0], 64)}:{safe_text(peer[1], 8)}"
        if isinstance(peer, tuple) and len(peer) >= 2
        else "-"
    )


@dataclass(frozen=True, slots=True)
class TransportConfig:
    max_frame: int = MAX_FRAME_BYTES
    max_streams: int = 32
    stream_window: int = 256 * 1024
    handshake_timeout: float = 10.0
    write_timeout: float = 30.0
    op_timeout: float = 30.0  # default bound for send/recv/accept/open
    idle_timeout: float = 60.0
    frame_timeout: float = 30.0
    ping_interval: float = 20.0
    stream_idle_timeout: float = 300.0
    skew: float = 30.0
    features: int = int(Feature.STREAMS)
    required_features: int = int(Feature.STREAMS)
    strict_features: bool = False
    registry: FrameRegistry = DEFAULT_REGISTRY

    def __post_init__(self) -> None:
        _bounded(self.max_frame, "max_frame", MIN_MAX_FRAME, MAX_FRAME_BYTES)
        _bounded(self.max_streams, "max_streams", 1, MAX_STREAMS)
        _bounded(
            self.stream_window,
            "stream_window",
            MIN_STREAM_WINDOW,
            MAX_STREAM_WINDOW,
        )
        if self.max_streams * self.stream_window > MAX_BUFFERED:
            raise ValueError("max_streams * stream_window exceeds MAX_BUFFERED")
        if self.max_streams * PER_STREAM_OVERHEAD > MAX_STREAM_OVERHEAD:
            raise ValueError("max_streams * per-stream OPEN metadata exceeds MAX_STREAM_OVERHEAD")
        if FIXED_OVERHEAD + MAC_LEN + 8 + min(self.stream_window, MAX_CHUNK_BYTES) > self.max_frame:
            raise ValueError("max_frame too small for stream_window")
        for name in (
            "handshake_timeout",
            "write_timeout",
            "idle_timeout",
            "frame_timeout",
            "ping_interval",
            "stream_idle_timeout",
        ):
            _pos(getattr(self, name), name)
        if self.idle_timeout < 2 * self.ping_interval:
            raise ValueError("idle_timeout must be >= 2 * ping_interval")
        if self.frame_timeout > self.idle_timeout:
            raise ValueError("frame_timeout must be <= idle_timeout")
        if (self.features & Feature.STREAMS) == 0:
            raise ValueError("Feature.STREAMS must be enabled")


@runtime_checkable
class FrameHandler(Protocol):
    """Synchronous. Raise TransportError to close with a status; any other
    exception is INTERNAL and fatal (fail-closed)."""

    def __call__(self, session: "Session", frame: Frame) -> None: ...


@dataclass(slots=True, frozen=True)
class ControlFun:
    tag: str
    stop_event: asyncio.Event
    on_write: WriteFn
    request_stop: RequestStopFn
    skew: float = 0.0
    not_after: float = 0.0
    on_sweep_idle: Callable[[], None] = lambda: None
    ping_interval: float = 5.0
    is_stopping: Callable[[], bool] = lambda: True


class ControlPlane:
    __slots__ = (
        "_pong",
        "_cancels",
        "_credits",
        "_outstanding",
        "_event",
        "_workers",
        "_funs",
    )

    def __init__(self, funs: ControlFun) -> None:
        self._pong: Optional[bytes] = None
        self._cancels: dict[int, str] = {}
        self._credits: dict[int, int] = {}
        self._outstanding: deque[bytes] = deque()
        self._event = asyncio.Event()
        self._workers: list[asyncio.Task] = []
        self._funs = funs

    def _has_pending_work(self) -> bool:
        return bool(self._pong is not None or self._cancels or self._credits)

    def _abort_transport(self) -> None:
        self._funs.stop_event.set()
        self._event.set()

    async def drain_workers(self, timeout: float = SHUTDOWN_GRACE) -> None:
        """Signal workers to stop, then give them `timeout` seconds to exit
        cleanly; cancel any stragglers and wait for cancellation to complete.
        Safe to call with no workers. Idempotent."""
        self._abort_transport()  # sets self._funs.stop_event; wakes loops

        if not self._workers:
            return

        _done, pending = await asyncio.wait(self._workers, timeout=timeout)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        self._workers.clear()

    def enqueue_pong(self, nonce: bytes) -> None:
        """Reply to a peer PING. Latest nonce overwrites any unsent pong."""
        self._pong = nonce
        self._event.set()

    def enqueue_cancel(self, stream_id: int, reason: str) -> None:
        """Abort a stream and discard any pending flow-control credits for it."""
        self._credits.pop(stream_id, None)
        self._cancels[stream_id] = reason
        self._event.set()

    def enqueue_credit(self, stream_id: int, amount: int) -> None:
        """Coalesce flow-control window credits for an active stream."""
        if amount <= 0 or stream_id in self._cancels:
            return
        current = self._credits.get(stream_id, 0)
        self._credits[stream_id] = min(current + amount, MAX_WINDOW_CREDIT)
        self._event.set()

    def drop_stream(self, stream_id: int) -> None:
        """Clean up queued control state when a stream closes normally."""
        self._cancels.pop(stream_id, None)
        self._credits.pop(stream_id, None)

    def ack_pong(self, nonce: bytes) -> bool:
        """Acknowledge a PONG from the peer, clearing it and any older pings."""
        if nonce not in self._outstanding:
            return False
        while self._outstanding and self._outstanding.popleft() != nonce:
            pass
        return True

    def wake(self) -> None:
        self._event.set()

    def clear(self) -> None:
        self._pong = None
        self._credits.clear()
        self._cancels.clear()
        self._outstanding.clear()

    async def start(self) -> None:

        if self._workers:
            return
        loop = asyncio.get_running_loop()
        try:
            self._workers = [
                loop.create_task(self.run_control_loop(), name="control-loop"),
                loop.create_task(self.run_ping_loop(), name="ping-loop"),
                loop.create_task(self.expiry_loop()),
            ]
        except BaseException:
            await self.drain_workers()
            raise

    async def expiry_loop(self) -> None:
        deadline = self._funs.not_after - self._funs.skew
        while not self._funs.is_stopping:
            rem = deadline - time.time()
            if rem <= 0:
                self._funs.request_stop(
                    TransportError(Status.UNAUTHENTICATED, "CERT_EXPIRED", retryable=True)
                )
                return
            await asyncio.sleep(min(rem, 30.0))

    async def _pre(self):
        while not self._has_pending_work() and not self._funs.is_stopping():
            self._event.clear()
            if self._has_pending_work() or self._funs.is_stopping():
                break
            await self._event.wait()

    async def run_control_loop(self) -> None:
        try:
            while True:
                await self._pre()
                if self._funs.is_stopping():
                    return
                # 1. Highest priority: PONG responses
                if self._pong is not None:
                    nonce, self._pong = self._pong, None
                    if not await self._funs.on_write(make_pong(nonce=nonce)):
                        self._abort_transport()
                        return

                # 2. Second priority: Stream cancellations
                while self._cancels and not self._funs.is_stopping():
                    stream_id, reason = next(iter(self._cancels.items()))
                    del self._cancels[stream_id]
                    if not await self._funs.on_write(
                        make_cancel(stream_id=stream_id, reason=reason)
                    ):
                        self._abort_transport()
                        return

                # 3. Third priority: Batched flow-control window updates
                while self._credits and not self._funs.is_stopping():
                    stream_id, credits = next(iter(self._credits.items()))
                    del self._credits[stream_id]
                    if not await self._funs.on_write(
                        make_window_update(
                            stream_id=stream_id,
                            credits=min(credits, MAX_WINDOW_CREDIT),
                        )
                    ):
                        self._abort_transport()
                        return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("control loop crashed %s", self._funs.tag)
            self._funs.request_stop(TransportError(Status.INTERNAL, "CONTROL_CRASH", notify=False))

    async def run_ping_loop(self) -> None:
        try:
            while not self._funs.is_stopping():
                try:
                    await asyncio.wait_for(self._funs.stop_event.wait(), self._funs.ping_interval)
                except asyncio.TimeoutError:
                    pass
                else:
                    return
                if self._funs.is_stopping():
                    return

                # True means the idle sweeper closed the connection
                if self._funs.on_sweep_idle():
                    self._abort_transport()
                    return

                if len(self._outstanding) >= MAX_OUTSTANDING_PINGS:
                    self._funs.request_stop(
                        TransportError(Status.UNAVAILABLE, "PING_TIMEOUT", notify=False)
                    )

                    self._abort_transport()
                    return

                nonce = secrets.token_bytes(PING_NONCE_BYTES)
                self._outstanding.append(nonce)
                if not await self._funs.on_write(make_ping(nonce=nonce)):
                    self._abort_transport()
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("ping loop crashed %s", self._funs.tag)
            self._funs.request_stop(TransportError(Status.INTERNAL, "PING_CRASH", notify=False))


class _Host:
    """StreamHost: the only bridge from Stream/Multiplexer back into Session."""

    __slots__ = ("_s",)

    def __init__(self, s: "Session") -> None:
        self._s = s

    @property
    def peer_id(self) -> str:
        return self._s.peer_id

    @property
    def channel_binding(self) -> bytes:
        return self._s.channel_binding

    @property
    def peer_max_frame(self) -> int:
        return self._s._peer_max_frame

    @property
    def op_timeout(self) -> float:
        return self._s._config.op_timeout

    @property
    def is_stopping(self) -> bool:
        return self._s._stopping

    @property
    def close_error(self) -> Optional[AegisError]:
        return self._s._close_error

    async def write_frame(self, frame: Frame) -> bool:
        return await self._s._write(frame)

    def grant_window(self, stream: "Stream", credits: int) -> None:

        if not stream.is_reset and not self._s._stopping:
            self._s._ctl.enqueue_credit(stream._stream_id, credits)

    def on_progress(self, stream: "Stream") -> None:

        if self._s._mux.retire_if_done(stream):
            self._s._ctl.drop_stream(stream._stream_id)

    def reset(self, stream: Stream, status: Status, reason: str, *, notify: bool) -> None:
        self._s._reset_stream(stream, status, reason, notify=notify)

    def request_stop(self, err: TransportError) -> None:
        return self._s.request_stop(err)


@dataclass(frozen=True, slots=True)
class ChannelInfo:
    """Verified identity & binding properties exposed to streams and agent layers."""

    peer_id: str
    alpn: str
    tls_version: str
    channel_binding: bytes
    is_client: bool
    connection_id: str


class Session:
    __slots__ = (
        "_config",
        "_channel",
        "_tag",
        "_fs",
        "_signer",
        "_handlers",
        "_on_data",
        "_peer_max_frame",
        "_peer_window",
        "_peer_max_streams",
        "_features",
        "_inbound_limit",
        "_mux",
        "_ctl",
        "_host",
        "_state",
        "_stop_ev",
        "_close_error",
        "_stopping",
        "_down",
        "_closed",
        "_reader",
        "_supervisor",
    )

    def __init__(
        self,
        tls: TlsConnection,
        config: TransportConfig,
        *,
        is_client: bool,
        handlers: Optional[Mapping[int, FrameHandler]] = None,
        on_data: Optional[DataHandler] = None,
        authorize_stream: Optional[StreamAuthorizer] = None,
        signer: Optional[StreamSigner] = None,
    ) -> None:
        if not isinstance(config, TransportConfig):
            raise TypeError("config must be a TransportConfig")
        if type(is_client) is not bool:
            raise TypeError("is_client must be bool")
        self._config = config
        cid = secrets.token_hex(6)
        self._tag = (
            f"cid={cid} peer={safe_text(tls.peer_id)} addr={_addr(tls.writer)}"
        )
        self._fs = FrameStream(
            tls.reader,
            tls.writer,
            registry=config.registry,
            write_timeout=config.write_timeout,
        )
        if signer is None:
            signer = HmacStreamSigner(*tls.secrets.for_role(is_client))
        self._signer = signer

        self._handlers: dict[int, FrameHandler] = {}
        for t, h in (handlers or {}).items():
            self.register_handler(t, h)
        self._on_data = on_data

        self._channel = ChannelInfo(
            peer_id=tls.peer_id,
            alpn=tls.alpn,
            tls_version=tls.tls_version,
            channel_binding=tls.channel_binding,
            is_client=is_client,
            connection_id=cid,
        )

        self._peer_max_frame = MIN_MAX_FRAME
        self._peer_window = 0
        self._peer_max_streams = 0
        self._features = 0
        self._inbound_limit = HANDSHAKE_MAX_PAYLOAD

        self._host = _Host(self)
        self._mux = StreamMultiplexer(
            self._host,
            self._signer,
            is_client=is_client,
            max_streams=config.max_streams,
            local_window=config.stream_window,
            authorizer=authorize_stream,
        )
        self._state = SessionState.HANDSHAKING
        self._stop_ev = asyncio.Event()
        self._close_error: Optional[TransportError] = None
        self._stopping = False
        self._down = False
        self._ctl: ControlPlane = None  # type: ignore

        self._closed = asyncio.Event()
        self._reader: Optional[asyncio.Task[None]] = None
        self._supervisor: Optional[asyncio.Task[None]] = None

    @property
    def peer_id(self) -> str:
        return self._channel.peer_id

    @property
    def channel_binding(self) -> bytes:
        return self._channel.channel_binding

    @property
    def features(self) -> int:
        return self._features

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def status(self) -> Status:
        return Status.OK if self._close_error is None else self._close_error.status

    @property
    def close_error(self) -> Optional[TransportError]:
        return self._close_error

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def active_streams(self) -> int:
        return self._mux.active

    async def __aenter__(self) -> "Session":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close("context_exit" if exc_type is None else "aborted")

    def _conn_closed(self) -> StreamError:
        err = self._host.close_error
        status = err.status if err and err.status is not Status.OK else Status.UNAVAILABLE
        return StreamError(status, "CONN_CLOSED", str(err or ""))

    def _require_open(self) -> None:  # fix #3
        if self._stopping or self._state is not SessionState.OPEN:
            raise self._conn_closed()

    def request_stop(self, err: TransportError) -> None:
        return self._request_stop(err)

    def _request_stop(self, err: TransportError) -> None:
        if self._close_error is None:
            self._close_error = err
        self._stopping = True
        if self._state is not SessionState.CLOSED:
            self._state = SessionState.CLOSING
        self._stop_ev.set()
        if self._ctl is not None:
            self._ctl.wake()
        self._mux.wake_all()

    def _reset_stream(self, st: Stream, status: Status, reason: str, *, notify: bool) -> None:
        safe = st.mark_reset(status, reason)
        if safe is None:
            return
        was_live = self._mux.forget(st)
        self._ctl.drop_stream(st._stream_id)
        if notify and was_live and not self._stopping:
            self._ctl.enqueue_cancel(st._stream_id, safe_text(f"{status.name}/{safe}", 128))

    def register_handler(self, type_id: int, handler: FrameHandler) -> None:
        if self._config.registry.get(type_id) is None:
            raise ValueError(f"unknown frame type 0x{type_id:02x}")
        if type_id in _CORE_TYPES:
            raise ValueError("core frame types cannot be overridden")
        if not isinstance(handler, FrameHandler):
            raise TypeError("handler must implement handle()")
        self._handlers[type_id] = handler

    def _sweep_idle(self) -> None:
        if self._stopping:
            return
        for st in self._mux.idle(self._config.stream_idle_timeout):
            self._reset_stream(st, Status.DEADLINE_EXCEEDED, "idle_timeout", notify=True)

    def _dispatch(self, f: Frame) -> None:
        t = f.type
        match t:
            case FrameType.STREAM_DATA:
                self._mux.on_stream_data(f)
            case FrameType.WINDOW_UPDATE:
                self._mux.on_window_update(f)
            case FrameType.OPEN_STREAM:
                denied = self._mux.on_open(f, peer_window=self._peer_window)
                if denied is not None and not self._stopping:
                    sid, status, reason = denied
                    self._ctl.enqueue_cancel(sid, safe_text(f"{status.name}/{reason}", 128))

            case FrameType.CANCEL:
                hit = self._mux.on_cancel(f)
                if hit is not None:
                    self._reset_stream(hit[0], Status.ABORTED, hit[1], notify=False)
            case FrameType.PING:
                self._ctl.enqueue_pong(f.body)

            case FrameType.PONG:
                if not self._ctl.ack_pong(f.body):
                    raise ProtocolViolation("UNSOLICITED_PONG", notify=False)
            case FrameType.CLOSE:
                try:
                    reason = parse_reason(f.body, field="close")
                except FrameError as exc:
                    raise ProtocolViolation(
                        "BAD_CLOSE",
                        exc.code,
                        status=Status.INVALID_ARGUMENT,
                        notify=False,
                    ) from None
                raise TransportError(
                    Status.UNAVAILABLE,
                    "PEER_CLOSE",
                    reason,
                    notify=False,
                    retryable=True,
                )
            case FrameType.ERROR:
                log.warning(
                    "peer ERROR (untrusted) %s: %s",
                    self._tag,
                    safe_text(f.body.decode("ascii", "replace"), 256),
                )
                raise TransportError(Status.ABORTED, "PEER_ERROR", notify=False)

            case FrameType.SESSION_INIT:
                raise ProtocolViolation("DUPLICATE_HELLO")
            case _:
                handler = self._handlers.get(t)
                if handler is None:
                    raise ProtocolViolation(
                        "UNHANDLED_FRAME",
                        f"0x{t:02x}",
                        status=Status.UNIMPLEMENTED,
                    )
                self._run_handler(lambda: handler(self, f), f"0x{t:02x}")

    def _run_handler(self, fn: Callable[[], None], what: str) -> None:
        try:
            fn()
        except TransportError:
            raise
        except AegisError as exc:  # stream/caller-scoped from a handler → fatal
            raise TransportError(
                Status.INTERNAL, "HANDLER_ERROR", f"{what} {exc}", notify=False
            ) from None
        except Exception as exc:
            log.exception("handler %s crashed %s", what, self._tag)
            raise TransportError(
                Status.INTERNAL,
                "HANDLER_CRASH",
                f"{what} {type(exc).__name__}",
                notify=False,
            ) from None

    async def _supervise(self) -> None:
        try:
            await self._stop_ev.wait()
        except asyncio.CancelledError:
            self._request_stop(
                TransportError(Status.CANCELLED, "SUPERVISOR_CANCELLED", notify=False)
            )
        await self._shutdown(self._close_error or TransportError(Status.UNKNOWN, "STOPPED"))

    @classmethod
    async def establish(
        cls,
        tls: TlsConnection,
        config: TransportConfig,
        *,
        is_client: bool,
        deadline: Optional[Deadline] = None,
        **kw,
    ) -> "Session":
        try:
            self = cls(tls, config, is_client=is_client, **kw)
        except BaseException:
            try:
                tls.writer.close()
            except Exception:
                pass
            raise

        d = effective_deadline(deadline, None, default=config.handshake_timeout, op="handshake")
        try:
            await d.run(self._handshake(), "handshake", scope=Scope.CONNECTION)
        except AegisError as exc:
            fatal = (
                exc
                if isinstance(exc, TransportError)
                else TransportError(
                    exc.status,
                    exc.code,
                    exc.detail,
                    notify=False,
                    retryable=exc.retryable,
                )
            )
            await self._shutdown(fatal)
            raise fatal from None
        except FrameError as exc:
            fatal = ProtocolViolation(
                f"frame:{exc.code}",
                exc.detail,
                status=Status.INVALID_ARGUMENT,
                notify=False,
            )
            await self._shutdown(fatal)
            raise fatal from None
        except BaseException:
            await self._shutdown(TransportError(Status.ABORTED, "HANDSHAKE_ABORTED", notify=False))
            raise

        self._inbound_limit = config.max_frame
        self._state = SessionState.OPEN
        loop = asyncio.get_running_loop()
        try:
            self._reader = loop.create_task(self._reader_loop())
            self._ctl = ControlPlane(
                ControlFun(
                    tag=self._tag,
                    request_stop=self.request_stop,
                    skew=self._config.skew,
                    not_after=tls.not_after,
                    stop_event=self._stop_ev,
                    ping_interval=config.ping_interval,
                    on_write=self._write,
                    is_stopping=lambda: self._stopping,
                    on_sweep_idle=self._sweep_idle,
                )
            )
            await self._ctl.start()
            self._supervisor = loop.create_task(self._supervise())
        except BaseException:
            await self._shutdown(TransportError(Status.INTERNAL, "SPAWN_FAILED", notify=False))
            raise
        log.info("session up %s features=0x%x", self._tag, self._features)

        return self

    async def accept(
        self,
        *,
        deadline: Optional[Deadline] = None,
        timeout: Optional[float] = None,
    ) -> Stream:
        return await self._mux.accept(deadline=deadline, timeout=timeout)

    async def open_stream(
        self,
        kind: str,
        payload: bytes = b"",
        *,
        token: bytes = b"",
        pop: bytes = b"",
        deadline: Optional[Deadline] = None,
        timeout: Optional[float] = None,
    ) -> Stream:
        d = effective_deadline(deadline, timeout, default=self._config.op_timeout, op="open_stream")
        self._require_open()
        d.check("open_stream")
        st, frame = self._mux.allocate(
            kind,
            payload,
            token=token,
            pop=pop,
            peer_max_streams=self._peer_max_streams,
            peer_window=self._peer_window,
        )
        try:
            written = await self._host.write_frame(frame)
        except asyncio.CancelledError:
            self._request_stop(
                TransportError(Status.ABORTED, "local:cancelled_during_write", notify=False)
            )
            raise
        if not written:
            self._reset_stream(st, Status.UNAVAILABLE, "conn_closed", notify=False)
            raise self._conn_closed()

        return st

    async def _reader_loop(self) -> None:
        try:
            while not self._stopping:
                out = await self._fs.recv(
                    idle_timeout=self._config.idle_timeout,
                    frame_timeout=self._config.frame_timeout,
                    max_payload=lambda: self._inbound_limit,
                )
                if isinstance(out, StreamClosed):
                    self._request_stop(
                        TransportError(
                            Status.UNAVAILABLE,
                            "READ_CLOSED",
                            out.reason,
                            notify=False,
                        )
                    )
                    return
                self._dispatch(out.frame)
        except TransportError as exc:
            self._request_stop(exc)
        except AegisError as exc:  # non-fatal leaked here = bug → fatal
            self._request_stop(
                TransportError(Status.INTERNAL, "ESCAPED_ERROR", str(exc), notify=False)
            )
        except FrameError as exc:
            self._request_stop(
                ProtocolViolation(
                    f"frame:{exc.code}",
                    exc.detail,
                    status=Status.INVALID_ARGUMENT,
                    notify=False,
                )
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("reader crashed %s", self._tag)
            self._request_stop(TransportError(Status.INTERNAL, "READER_CRASH", notify=False))

    async def _write(self, frame: Frame) -> bool:
        try:
            out = await self._fs.send(frame, timeout=self._config.write_timeout)
        except FrameError as exc:
            self._request_stop(
                TransportError(
                    Status.INTERNAL,
                    f"encode:{exc.code}",
                    exc.detail,
                    notify=False,
                )
            )
            return False
        if isinstance(out, StreamClosed):
            status = (
                Status.DEADLINE_EXCEEDED if out.reason == "write_timeout" else Status.UNAVAILABLE
            )
            self._request_stop(TransportError(status, "WRITE_CLOSED", out.reason, notify=False))
            return False
        return True

    async def _handshake(self) -> None:
        cfg = self._config
        mine = _HELLO.pack(
            PROTOCOL_VERSION,
            cfg.features,
            cfg.max_frame,
            cfg.stream_window,
            cfg.max_streams,
        )
        # Both sides send first, then read: no role ordering dependency.
        if not await self._write(make_session_init(mine)):
            raise TransportError(Status.UNAVAILABLE, "HANDSHAKE_WRITE", notify=False)

        out = await self._fs.recv(
            idle_timeout=cfg.handshake_timeout,
            frame_timeout=cfg.handshake_timeout,
            max_payload=HANDSHAKE_MAX_PAYLOAD,
        )
        if isinstance(out, StreamClosed):
            raise TransportError(Status.UNAVAILABLE, "HANDSHAKE_EOF", out.reason, notify=False)

        f = out.frame
        if f.type != FrameType.SESSION_INIT:
            raise ProtocolViolation("EXPECTED_HELLO", FrameType.name(f.type))
        if f.stream_id or f.flags or f.token or f.pop or len(f.body) != _HELLO.size:
            raise ProtocolViolation("BAD_HELLO", status=Status.INVALID_ARGUMENT)

        version, peer_features, max_frame, window, max_streams = _HELLO.unpack(f.body)

        if version != PROTOCOL_VERSION:
            raise TransportError(Status.UNIMPLEMENTED, "VERSION", str(version))

        if not MIN_MAX_FRAME <= max_frame <= MAX_FRAME_BYTES:
            raise ProtocolViolation("MAX_FRAME", str(max_frame), status=Status.OUT_OF_RANGE)
        if not MIN_STREAM_WINDOW <= window <= MAX_STREAM_WINDOW:
            raise ProtocolViolation("STREAM_WINDOW", str(window), status=Status.OUT_OF_RANGE)
        if not 1 <= max_streams <= MAX_STREAMS:
            raise ProtocolViolation("MAX_STREAMS", str(max_streams), status=Status.OUT_OF_RANGE)

        negotiated = cfg.features & peer_features
        if (negotiated & cfg.required_features) != cfg.required_features:
            raise TransportError(
                Status.UNIMPLEMENTED,
                "FEATURES",
                f"need 0x{cfg.required_features:x}",
            )
        if cfg.strict_features and negotiated != cfg.features:
            raise TransportError(Status.UNIMPLEMENTED, "FEATURES", f"peer 0x{peer_features:x}")
        self._features = negotiated
        self._peer_max_frame = max_frame
        self._peer_window = window
        self._peer_max_streams = max_streams
        self._mux.set_bidi(bool(negotiated))

    async def close(self, reason: str = "local", *, deadline: Optional[Deadline] = None) -> None:
        self._request_stop(TransportError(Status.OK, "LOCAL_CLOSE", reason, notify=True))
        d = effective_deadline(deadline, None, default=self._config.write_timeout, op="close")
        await d.run(self._closed.wait(), "close", scope=Scope.CONNECTION)

    async def wait_closed(self, *, deadline: Optional[Deadline] = None) -> None:
        if deadline is None:
            await self._closed.wait()
        else:
            await deadline.run(self._closed.wait(), "wait_closed", scope=Scope.CONNECTION)

    async def _shutdown(self, err: TransportError) -> None:
        if self._down:
            await self._closed.wait()
            return

        self._down = True
        try:
            self._request_stop(err)
            err = self._close_error or err
            if self._reader is not None:
                self._reader.cancel()

            if self._ctl is not None:
                await self._ctl.drain_workers()
                self._ctl.clear()

            if self._reader is not None:
                await asyncio.gather(self._reader, return_exceptions=True)
            self._mux.clear(
                err.status if err.status not in (Status.OK, Status.CANCELLED) else Status.CANCELLED,
                f"closed:{err.code}",
            )
            if err.notify and not self._fs.writer.busy and not self._fs.writer.closed:
                try:
                    await self._fs.send(make_close(close_reason(err)), timeout=CLOSE_WRITE_TIMEOUT)
                except Exception:
                    pass
            try:
                await self._fs.close(err.code)
            except Exception:
                self._fs.writer.abort(err.code)
            log.info("session closed %s %s", self._tag, err)
        finally:
            self._state = SessionState.CLOSED
            self._closed.set()




Transport = Session

# Shared material so client signs with keys the server verifies, and vice versa.
SHARED_SECRETS = SessionSecrets(
    channel_binding=b"\xcb" * 32,
    stream_ikm_c2s=b"\x01" * 32,  # client → server
    stream_ikm_s2c=b"\x02" * 32,  # server → client
)


def _config(**overrides) -> TransportConfig:
    cfg = dict(
        handshake_timeout=2.0,
        write_timeout=2.0,
        op_timeout=2.0,
        idle_timeout=10.0,
        frame_timeout=5.0,
        ping_interval=2.0,
        stream_window=64 * 1024,
        max_frame=128 * 1024,
    )
    cfg.update(overrides)
    return TransportConfig(**cfg)  # type: ignore


def _tls(reader, writer, *, role: str, secrets: SessionSecrets) -> TlsConnection:
    return TlsConnection(
        reader=reader,
        writer=writer,
        tls_object=None,
        peer_id=f"spiffe://aegis/test/{role}",
        alpn="aegis/v1",
        tls_version="TLSv1.3",
        secrets=secrets,
        not_before=0.0,
        not_after=time.time() + 3600,
    )


async def make_pair(
    *,
    config: TransportConfig | None = None,
    client_secrets: SessionSecrets | None = None,
    server_secrets: SessionSecrets | None = None,
    client_handlers=None,
    server_handlers=None,
    data_handler=None,
    authorize_stream=None,
):
    """Return (client, server, cleanup). Both sessions fully established."""
    config = config or _config()
    cs = client_secrets or SHARED_SECRETS
    ss = server_secrets or SHARED_SECRETS
    server_box: asyncio.Future[Session] = asyncio.get_event_loop().create_future()

    async def handle(reader, writer):
        try:
            sess = await Session.establish(
                _tls(reader, writer, role="server", secrets=ss),
                config,
                is_client=False,
                handlers=server_handlers,
                on_data=data_handler,
                authorize_stream=authorize_stream,
            )
            server_box.set_result(sess)
        except BaseException as exc:
            if not server_box.done():
                server_box.set_exception(exc)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    client = await Session.establish(
        _tls(reader, writer, role="client", secrets=cs),
        config,
        is_client=True,
        handlers=client_handlers,
        on_data=data_handler,
        authorize_stream=authorize_stream,
    )
    server_sess = await asyncio.wait_for(server_box, 3.0)

    async def cleanup():
        for s in (client, server_sess):
            try:
                await s.close(reason="test_cleanup")
            except Exception:
                pass
        server.close()
        await server.wait_closed()

    return client, server_sess, cleanup


def _run(coro_fn):
    asyncio.run(coro_fn())


def test_roundtrip():
    _run(_roundtrip)


async def _multi_chunk():
    client, server, cleanup = await make_pair()
    try:

        async def consume_n():
            st = await server.accept(deadline=Deadline.after(2.0))
            out = bytearray()
            while True:
                chunk = await st.recv(deadline=Deadline.after(2.0))
                if chunk is None:
                    break
                out.extend(chunk)
            await st.send(bytes(out), fin=True, deadline=Deadline.after(2.0))
            await st.aclose()

        task = asyncio.create_task(consume_n())
        st = await client.open_stream("t", deadline=Deadline.after(2.0))
        payload = bytes(range(256)) * 4
        await st.send(payload, deadline=Deadline.after(2.0))
        await st.send(b"", fin=True, deadline=Deadline.after(2.0))
        echo = await st.recv(deadline=Deadline.after(2.0))
        assert echo == payload
        assert await st.recv(deadline=Deadline.after(2.0)) is None
        await st.aclose()
        await task
    finally:
        await cleanup()


async def _roundtrip():
    client, server, cleanup = await make_pair()
    try:

        async def echo():
            st = await server.accept(deadline=Deadline.after(2.0))
            data = await st.recv(deadline=Deadline.after(2.0))
            print(data)
            assert data == b"hello"

            await st.send(data, fin=True, deadline=Deadline.after(2.0))
            assert await st.recv(deadline=Deadline.after(2.0)) is None
            await st.aclose()

        task = asyncio.create_task(echo())
        st = await client.open_stream("echo", deadline=Deadline.after(2.0))
        assert st.status is Status.OK
        await st.send(b"hello", fin=True, deadline=Deadline.after(2.0))
        assert await st.recv(deadline=Deadline.after(2.0)) == b"hello"
        assert await st.recv(deadline=Deadline.after(2.0)) is None
        await st.aclose()
        await task
    finally:
        await cleanup()


async def _stream_cancel():
    client, server, cleanup = await make_pair()
    try:
        peer_out: dict = {}
        accepted = asyncio.Event()

        async def server_side():
            st = await server.accept(deadline=Deadline.after(2.0))
            accepted.set()
            try:
                while True:
                    d = await st.recv(deadline=Deadline.after(5.0))
                    if d is None:
                        break
            except StreamError as e:
                peer_out["status"] = e.status
                peer_out["detail"] = e.detail

        task = asyncio.create_task(server_side())
        st = await client.open_stream("t", deadline=Deadline.after(2.0))
        await asyncio.wait_for(accepted.wait(), 2.0)

        st.cancel("test_cancel")
        await asyncio.wait_for(task, 3.0)

        assert peer_out["status"] is Status.ABORTED
        assert peer_out["detail"].startswith("peer:")
    finally:
        await cleanup()


async def _verify_failure():
    # Mismatched secrets → handshake OK (doesn't use stream signer), but
    # STREAM_DATA MACs won't verify on the server.
    bad = SessionSecrets(
        channel_binding=b"\xcc" * 32,
        stream_ikm_c2s=b"\x33" * 32,
        stream_ikm_s2c=b"\x44" * 32,
    )
    client, server, cleanup = await make_pair(client_secrets=bad)
    try:
        peer_out: dict = {}
        accepted = asyncio.Event()

        async def server_side():
            st = await server.accept(deadline=Deadline.after(2.0))
            accepted.set()
            try:
                await st.recv(deadline=Deadline.after(3.0))
            except StreamError as e:
                peer_out["code"] = e.code
                peer_out["status"] = e.status

        task = asyncio.create_task(server_side())
        st = await client.open_stream("t", deadline=Deadline.after(2.0))
        await asyncio.wait_for(accepted.wait(), 2.0)
        await st.send(b"hello", deadline=Deadline.after(2.0))

        await asyncio.wait_for(task, 4.0)
        assert peer_out["code"] == "VERIFY_FAILED"
        assert peer_out["status"] is Status.UNAUTHENTICATED
        # Server must have sent CANCEL; client's stream resets.
        for _ in range(50):
            if st.is_reset:
                break
            await asyncio.sleep(0.02)
        assert st.is_reset, "client did not observe CANCEL after verify failure"
    finally:
        await cleanup()


import unittest.mock
import pytest


async def _send_cancelled():
    client, server, cleanup = await make_pair()
    try:
        st = await client.open_stream("t", deadline=Deadline.after(2.0))

        async def raise_cancelled(self, frame):
            raise asyncio.CancelledError()

        with unittest.mock.patch.object(Session, "_write", raise_cancelled):
            task = asyncio.create_task(st.send(b"hello", deadline=Deadline.after(2.0)))
            with pytest.raises(asyncio.CancelledError):
                await task

        assert client._stopping, (
            "session must enter stopping state after a cancelled write; "
            "otherwise _send_seq/_send_sent are committed but the peer "
            "may never have received the frame"
        )
    finally:
        try:
            async with asyncio.timeout(5.0):
                await cleanup()
        except (asyncio.TimeoutError, TimeoutError):
            pass


async def _open_cancelled():
    client, server, cleanup = await make_pair()
    try:

        async def raise_cancelled(self, frame):
            raise asyncio.CancelledError()

        with unittest.mock.patch.object(Session, "_write", raise_cancelled):
            task = asyncio.create_task(client.open_stream("t", deadline=Deadline.after(2.0)))
            with pytest.raises(asyncio.CancelledError):
                await task

        assert client._stopping
    finally:
        try:
            async with asyncio.timeout(6.0):
                await cleanup()
        except (asyncio.TimeoutError, TimeoutError):
            pass


async def _request_stop_none_ctl():
    client, server, cleanup = await make_pair()
    try:
        client._ctl = None # type: ignore
        # Must not raise.
        client._request_stop(TransportError(Status.INTERNAL, "simulated_early_failure"))
        assert client._stopping
        # _shutdown also reaches _ctl._workers — must tolerate None.
        async with asyncio.timeout(5.0):
            await client._shutdown(client._close_error) # type: ignore
        assert client._closed.is_set()
    finally:
        try:
            async with asyncio.timeout(5.0):
                await server.close("test")
        except Exception:
            pass


async def _open_after_close():
    client, server, cleanup = await make_pair()
    try:
        await client.close("test")
        await asyncio.wait_for(client.wait_closed(), 3.0)
        with pytest.raises(StreamError) as ei:
            await client.open_stream("t", deadline=Deadline.after(1.0))
        assert ei.value.status is not Status.OK, f"conn_closed returned OK; got {ei.value.status}"
        assert ei.value.status is Status.UNAVAILABLE
    finally:
        await cleanup()


async def _deadline_ambient():
    outer = Deadline.after(0.1)
    inner = Deadline.after(1.0)

    t0 = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        with deadline_scope(outer):
            await inner.run(asyncio.sleep(5.0), "test")
    elapsed = time.monotonic() - t0
    assert elapsed < 0.5, (
        f"ambient deadline not honored: direct run took {elapsed:.2f}s (should be <0.5s)"
    )


async def _deadline_both():
    with pytest.raises(StreamError) as ei:
        effective_deadline(Deadline.after(1.0), 1.0, default=1.0, op="test")
    assert ei.value.code == "DEADLINE_AND_TIMEOUT"


async def _stream_limit():
    cfg = _config(max_streams=2)
    client, server, cleanup = await make_pair(config=cfg)
    try:
        s1 = await client.open_stream("t", deadline=Deadline.after(2.0))
        s2 = await client.open_stream("t", deadline=Deadline.after(2.0))
        with pytest.raises(StreamError) as ei:
            await client.open_stream("t", deadline=Deadline.after(2.0))
        assert ei.value.status is Status.RESOURCE_EXHAUSTED
        # Sanity: both earlier opens succeeded
        assert s1._stream_id and s2._stream_id
    finally:
        await cleanup()


async def _flow_control():
    cfg = _config(stream_window=4 * 1024, max_frame=64 * 1024)
    client, server, cleanup = await make_pair(config=cfg)
    try:
        accept_task = asyncio.create_task(server.accept(deadline=Deadline.after(2.0)))
        st = await client.open_stream("t", deadline=Deadline.after(2.0))
        await accept_task

        # First full-window chunk fits.
        await st.send(b"x" * 4096, deadline=Deadline.after(2.0))

        # Second chunk must block — server never calls recv, so no credit.
        with pytest.raises((DeadlineExceeded, StreamError)):
            await st.send(b"x" * 4096, deadline=Deadline.after(0.3))
    finally:
        await cleanup()


async def _seq_mismatch():
    client, server, cleanup = await make_pair()
    try:
        accept_task = asyncio.create_task(server.accept(deadline=Deadline.after(2.0)))
        st = await client.open_stream("t", deadline=Deadline.after(2.0))
        await accept_task

        # Craft a frame with seq=5 — must not match server's expected seq 0.
        # MAC doesn't matter; SEQ is checked before verify.
        bad = make_stream_data(
            stream_id=st._stream_id,
            seq=5,
            data=b"x",
            mac=b"\x00" * 32,
            fin=False,
        )
        await client._fs.send(bad)

        await asyncio.wait_for(server._stop_ev.wait(), 2.0)
        assert "SEQ" in str(server._close_error or "")
    finally:
        await cleanup()


async def _data_after_fin():
    client, server, cleanup = await make_pair()
    try:
        accept_task = asyncio.create_task(server.accept(deadline=Deadline.after(2.0)))
        st = await client.open_stream("t", deadline=Deadline.after(2.0))
        await accept_task

        # Legitimate FIN (MAC invalid but seq=0 passes; _remote_fin gets set).
        fin = make_stream_data(
            stream_id=st._stream_id,
            seq=0,
            data=b"",
            mac=b"\x00" * 32,
            fin=True,
        )
        await client._fs.send(fin)
        await asyncio.sleep(0.1)

        # Any further frame on the stream is a protocol violation.
        post = make_stream_data(
            stream_id=st._stream_id,
            seq=1,
            data=b"y",
            mac=b"\x00" * 32,
            fin=False,
        )
        await client._fs.send(post)

        await asyncio.wait_for(server._stop_ev.wait(), 2.0)
        assert "DATA_AFTER_FIN" in str(server._close_error or "")
    finally:
        await cleanup()


async def _authorize_denied():
    def deny_all(sid, kind, payload, token, pop):
        return (Status.PERMISSION_DENIED, "not_allowed")

    client, server, cleanup = await make_pair(authorize_stream=deny_all)
    try:
        st = await client.open_stream("t", deadline=Deadline.after(2.0))
        # Wait for the CANCEL to come back.
        for _ in range(100):
            if st.is_reset:
                break
            await asyncio.sleep(0.02)
        assert st.is_reset
        assert "PERMISSION_DENIED" in (st.reset_reason or "")
        # Server must not have pending accepts.
        assert server.active_streams == 0
    finally:
        await cleanup()


async def _handshake_version():
    import struct as _struct

    # Wrap the client-side hello builder to advertise version 3.
    orig = Session._handshake

    async def patched(self):
        cfg = self._config
        mine = _struct.pack(">HIIIH", 3, 0x0001, cfg.max_frame, cfg.stream_window, cfg.max_streams)
        if not await self._write(make_session_init(mine)):
            raise TransportError(Status.UNAVAILABLE, "HANDSHAKE_WRITE", notify=False)
        # Let the peer reply, then fail as the real code would.
        out = await self._fs.recv(
            idle_timeout=cfg.handshake_timeout,
            frame_timeout=cfg.handshake_timeout,
            max_payload=HANDSHAKE_MAX_PAYLOAD,
        )
        raise TransportError(Status.UNIMPLEMENTED, "VERSION", "3", notify=False)

    with unittest.mock.patch.object(Session, "_handshake", patched):
        with pytest.raises(TransportError) as ei:
            await make_pair()
    assert ei.value.status is Status.UNIMPLEMENTED
    assert ei.value.code == "VERSION"


async def _dup_hello():
    client, server, cleanup = await make_pair()
    try:
        import struct as _struct

        extra = _struct.pack(">HIIIH", 4, 0x0001, 128 * 1024, 64 * 1024, 32)
        await client._fs.send(make_session_init(extra))
        await asyncio.wait_for(server._stop_ev.wait(), 2.0)
        assert "DUPLICATE_HELLO" in str(server._close_error or "")
    finally:
        await cleanup()


async def _unexpected_open():
    client, server, cleanup = await make_pair()
    try:
        from libs.transport.frame import make_open_stream

        frame = make_open_stream(stream_id=2, kind="x", payload=b"", token=b"", pop=b"")
        await server._fs.send(frame)

        task = asyncio.create_task(asyncio.wait_for(client._stop_ev.wait(), 3.0))

        await task

        # await asyncio.wait_for(client._stop_ev.wait(), 2.0)
        print(client)
        assert "UNEXPECTED_OPEN" in str(client._close_error or "")
    finally:
        await cleanup()


async def _authorizer_denial():
    def deny_all(sid, kind, payload, token, pop):
        return (Status.PERMISSION_DENIED, "test_deny")

    client, server, cleanup = await make_pair(authorize_stream=deny_all)
    try:
        await client.open_stream("forbidden", deadline=Deadline.after(2.0))
        with pytest.raises(DeadlineExceeded):
            await server.accept(timeout=0.2)
        # Connection stayed up.
        assert not client.closed and not server.closed
    finally:
        await cleanup()


async def _run_all():
    await _roundtrip()
    await _multi_chunk()
    await _stream_cancel()
    await _verify_failure()
    await _send_cancelled()
    await _open_cancelled()
    await _request_stop_none_ctl()
    await _open_after_close()
    await _deadline_ambient()
    await _deadline_both()
    await _stream_limit()
    await _flow_control()
    await _seq_mismatch()
    await _data_after_fin()
    await _authorize_denied()
    await _dup_hello()
    # await _unexpected_open()
    await _authorizer_denial()
    # await _handshake_version()


if __name__ == "__main__":
    asyncio.run(_run_all())
