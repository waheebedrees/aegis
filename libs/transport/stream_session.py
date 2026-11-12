"""libs/transport/stream/stream_session.py — multiplexed session over the v4 framing.

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

import asyncio
import hashlib
import hmac
import logging
import math
import secrets
import struct
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from libs.transport.frame import (
    FIXED_OVERHEAD,
    MAX_CHUNK_BYTES,
    MAX_FRAME_BYTES,
    MAX_SEQ,
    MAX_STREAM_ID,
    MAX_WINDOW_CREDIT,
    OPEN_MAX_BODY,
    OPEN_MAX_POP,
    OPEN_MAX_TOKEN,
    PING_NONCE_BYTES,
    STREAM_MAC_BYTES,
    Flags,
    Frame,
    FrameError,
    FrameStream,
    FrameType,
    StreamClosed,
    make_cancel,
    make_close,
    make_open_stream,
    make_ping,
    make_pong,
    make_session_init,
    make_stream_data,
    make_window_update,
    parse_open_stream_body,
    parse_reason,
    parse_stream_data,
    parse_window_update,
)
from libs.transport.tls import TlsConnection

log = logging.getLogger(__name__)

__all__ = [
    "PROTOCOL_VERSION",
    "TransportConfig",
    "TransportError",
    "StreamError",
    "StreamSigner",
    "HmacStreamSigner",
    "Stream",
    "Transport",
]

PROTOCOL_VERSION = 4
FEATURE_STREAMS = 0x0001
FEATURES = FEATURE_STREAMS            # exact match; unknown bits are rejected

MAC_LEN = STREAM_MAC_BYTES
MIN_MAX_FRAME = 64 * 1024
MIN_STREAM_WINDOW = 4 * 1024
MAX_STREAM_WINDOW = 1024 * 1024
MAX_STREAMS = 256
MAX_BUFFERED = 32 * 1024 * 1024       # per side, data buffers only
PER_STREAM_OVERHEAD = OPEN_MAX_TOKEN + OPEN_MAX_POP + OPEN_MAX_BODY
MAX_STREAM_OVERHEAD = 4 * 1024 * 1024  # per side, retained OPEN metadata

HANDSHAKE_MAX_PAYLOAD = FIXED_OVERHEAD + 64
CLOSE_WRITE_TIMEOUT = 1.0
SHUTDOWN_GRACE = 0.5
MAX_OUTSTANDING_PINGS = 3
MAX_STALE_BYTES = 8 * 1024 * 1024
RETIRED_RING_FACTOR = 8

# SESSION_INIT body: version, features, max_frame, stream_window, max_streams
_HELLO = struct.Struct(">HIIIH")
_CHUNK_DOMAIN = b"aegis/stream-chunk/v4"
_CHUNK_HDR = struct.Struct(">IQBI")   # stream_id, seq, fin, len(data)


class TransportError(Exception):
    """Connection-fatal. `notify` says whether a CLOSE may be sent back."""

    __slots__ = ("code", "detail", "notify")

    def __init__(self, code: str, detail: str = "", *, notify: bool = True) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.notify = notify


class StreamError(Exception):
    """Stream-scoped failure or local misuse. The connection stays up."""

    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _safe(text: object, limit: int = 128) -> str:
    return "".join(c if " " <= c <= "~" else "_" for c in str(text)[:limit])


def _addr(writer: object) -> str:
    try:
        peer = writer.get_extra_info("peername")  # type: ignore[attr-defined]
    except Exception:
        return "-"
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{_safe(peer[0], 64)}:{_safe(peer[1], 8)}"
    return "-"


def _pos(value: object, name: str) -> None:
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0: # type: ignore
        raise ValueError(f"{name} must be a finite positive number")


def _bounded(value: object, name: str, lo: int, hi: int) -> None:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{name} must be an int in {lo}..{hi}")


# ───────────────────────── chunk authentication ─────────────────────────

@runtime_checkable
class StreamSigner(Protocol):
    """Authenticates outbound chunks and verifies inbound ones.

    Implementations MUST bind at least (direction, stream_id, seq, fin, data).
    sign() must be a pure function of its arguments: the transport calls it
    exactly once per (stream_id, seq) and never retries.
    """

    def sign(self, stream_id: int, seq: int, fin: bool, data: bytes) -> bytes: ...

    def verify(
        self, stream_id: int, seq: int, fin: bool, data: bytes, mac: bytes
    ) -> None: ...


class HmacStreamSigner:
    """Default signer. Direction-separated HMAC-SHA256 over an unambiguous,
    length-prefixed encoding of (stream_id, seq, fin, len(data), data).

    The send and receive keys are distinct halves of the TLS exporter split,
    so a peer cannot reflect our own chunks back at us, and a chunk is bound
    to its stream id, so it cannot be replayed onto another stream.
    """

    __slots__ = ("_send_key", "_recv_key")

    def __init__(self, send_ikm: bytes, recv_ikm: bytes) -> None:
        for k in (send_ikm, recv_ikm):
            if not isinstance(k, (bytes, bytearray)) or len(k) < 32:
                raise ValueError("stream keys must be at least 32 bytes")
        if hmac.compare_digest(bytes(send_ikm), bytes(recv_ikm)):
            raise ValueError("send and receive keys must differ")
        self._send_key = bytes(send_ikm)
        self._recv_key = bytes(recv_ikm)

    @staticmethod
    def _mac(key: bytes, stream_id: int, seq: int, fin: bool, data: bytes) -> bytes:
        h = hmac.new(key, None, hashlib.sha256)
        h.update(_CHUNK_DOMAIN)
        h.update(_CHUNK_HDR.pack(stream_id, seq, 1 if fin else 0, len(data)))
        h.update(data)
        return h.digest()

    def sign(self, stream_id: int, seq: int, fin: bool, data: bytes) -> bytes:
        return self._mac(self._send_key, stream_id, seq, fin, data)

    def verify(
        self, stream_id: int, seq: int, fin: bool, data: bytes, mac: bytes
    ) -> None:
        expected = self._mac(self._recv_key, stream_id, seq, fin, data)
        if not hmac.compare_digest(expected, mac):
            raise StreamError("MAC_MISMATCH", str(stream_id))


@dataclass(frozen=True, slots=True)
class TransportConfig:
    max_frame: int = MAX_FRAME_BYTES
    max_streams: int = 32
    stream_window: int = 256 * 1024
    handshake_timeout: float = 10.0
    write_timeout: float = 30.0
    idle_timeout: float = 60.0
    frame_timeout: float = 30.0
    ping_interval: float = 20.0
    stream_idle_timeout: float = 300.0
    skew: float = 30.0

    
    def __post_init__(self) -> None:
        _bounded(self.max_frame, "max_frame", MIN_MAX_FRAME, MAX_FRAME_BYTES)
        _bounded(self.max_streams, "max_streams", 1, MAX_STREAMS)
        _bounded(self.stream_window, "stream_window",
                 MIN_STREAM_WINDOW, MAX_STREAM_WINDOW)
        if self.max_streams * self.stream_window > MAX_BUFFERED:
            raise ValueError("max_streams * stream_window exceeds MAX_BUFFERED")
        if self.max_streams * PER_STREAM_OVERHEAD > MAX_STREAM_OVERHEAD:
            raise ValueError("max_streams * per-stream OPEN metadata exceeds "
                             "MAX_STREAM_OVERHEAD")
        # A single maximal chunk must fit in our own advertised frame size,
        # otherwise the peer could never use the window we advertise.
        if FIXED_OVERHEAD + MAC_LEN + 8 + min(self.stream_window, MAX_CHUNK_BYTES) > self.max_frame:
            raise ValueError("max_frame too small for stream_window")
        for name in ("handshake_timeout", "write_timeout", "idle_timeout",
                     "frame_timeout", "ping_interval", "stream_idle_timeout"):
            _pos(getattr(self, name), name)
        if self.idle_timeout < 2 * self.ping_interval:
            raise ValueError("idle_timeout must be >= 2 * ping_interval")
        if self.frame_timeout > self.idle_timeout:
            raise ValueError("frame_timeout must be <= idle_timeout")


class Stream:
    """One bidirectional stream. Created only by Transport.open_stream (client)
    or delivered by Transport.accept (server)."""

    __slots__ = (
        "_t", "_sid", "_kind", "_peer_window", "_window",
        "_open_body", "_open_payload", "_open_token", "_open_pop", "_signer",
        "_send_seq", "_send_sent", "_send_granted", "_send_fin",
        "_send_lock", "_send_ev",
        "_recv_seq", "_recv_buffered", "_buf", "_remote_fin",
        "_recv_lock", "_recv_ev", "_reset", "_touched",
    )

    def __init__(
        self,
        transport: "Transport",
        sid: int,
        *,
        kind: str,
        peer_window: int,
        window: int,
        open_body: bytes,
        open_payload: bytes,
        open_token: bytes,
        open_pop: bytes,
        signer: StreamSigner,
    ) -> None:
        self._t = transport
        self._sid = sid
        self._kind = kind
        self._peer_window = peer_window      # our send budget (peer's advert)
        self._window = window                # our receive budget (our config)
        self._open_body = open_body
        self._open_payload = open_payload
        self._open_token = open_token
        self._open_pop = open_pop
        self._signer = signer
        self._send_seq = 0
        self._send_sent = 0                  # payload bytes written
        self._send_granted = 0               # payload bytes credited by peer
        self._send_fin = False
        self._send_lock = asyncio.Lock()
        self._send_ev = asyncio.Event()
        self._recv_seq = 0
        self._recv_buffered = 0              # arrived, not yet dequeued
        self._buf: deque[tuple[int, bytes, bool, bytes]] = deque()
        self._remote_fin = False
        self._recv_lock = asyncio.Lock()
        self._recv_ev = asyncio.Event()
        self._reset: Optional[str] = None
        self._touched = time.monotonic()

    # read-only views

    @property
    def sid(self) -> int:
        return self._sid

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def open_payload(self) -> bytes:
        return self._open_payload

    @property
    def open_token(self) -> bytes:
        return self._open_token

    @property
    def open_pop(self) -> bytes:
        return self._open_pop

    @property
    def reset_reason(self) -> Optional[str]:
        return self._reset

    @property
    def send_closed(self) -> bool:
        return self._send_fin or self._reset is not None

    @property
    def recv_closed(self) -> bool:
        return (self._remote_fin and not self._buf) or self._reset is not None

    @property
    def peer_id(self):
        return self._t.peer_id
    
    def __repr__(self) -> str:
        return (f"<Stream sid={self._sid} kind={self._kind!r} "
                f"reset={self._reset!r}>")

    def set_signer(self, signer: StreamSigner) -> None:
        """Override the default exporter-derived signer. Must be called before
        the first send or recv on this stream."""
        if self._send_seq or self._recv_seq or self._buf:
            raise StreamError("ALREADY_ACTIVE")
        if not isinstance(signer, StreamSigner):
            raise StreamError("BAD_SIGNER")
        self._signer = signer

    # send

    async def send(
        self, data: bytes, *, fin: bool = False, timeout: Optional[float] = None
    ) -> None:
        if type(data) is not bytes:
            raise StreamError("BAD_DATA", type(data).__name__)
        if type(fin) is not bool:
            raise StreamError("BAD_FIN")
        if len(data) > MAX_CHUNK_BYTES:
            raise StreamError("CHUNK_TOO_LARGE", str(len(data)))
        if not data and not fin:
            raise StreamError("EMPTY_CHUNK")
        if len(data) > self._peer_window:
            raise StreamError("CHUNK_EXCEEDS_WINDOW", str(len(data)))
        if FIXED_OVERHEAD + MAC_LEN + 8 + len(data) > self._t._peer_max_frame:
            raise StreamError("FRAME_TOO_LARGE_FOR_PEER", str(len(data)))

        async with self._send_lock:
            self._check_sendable()
            if timeout is None:
                await self._await_credit(len(data))
            else:
                try:
                    await asyncio.wait_for(self._await_credit(len(data)), timeout)
                except asyncio.TimeoutError:
                    raise StreamError("CREDIT_TIMEOUT", str(self._sid)) from None
            self._check_sendable()

            seq = self._send_seq
            if seq > MAX_SEQ:
                raise StreamError("SEQ_EXHAUSTED", str(self._sid))

            # Sign before mutating any state: a raising signer leaves the
            # stream exactly as it was.
            try:
                mac = self._signer.sign(self._sid, seq, fin, data)
            except StreamError:
                raise
            except BaseException as exc:
                raise StreamError("SIGN_FAILED", type(exc).__name__) from None
            if type(mac) is not bytes or len(mac) != MAC_LEN:
                raise StreamError("BAD_MAC")

            frame = make_stream_data(
                stream_id=self._sid, seq=seq, data=data, mac=mac, fin=fin
            )

            # Commit before the write. A failed write tears the whole
            # connection down, so no partial state can survive it.
            self._send_seq = seq + 1
            self._send_sent += len(data)
            if fin:
                self._send_fin = True
            self._touched = time.monotonic()

            if not await self._t._write(frame):
                raise StreamError("CONN_CLOSED", self._t.close_reason or "")
            self._t._retire_if_done(self)

    async def _await_credit(self, n: int) -> None:
        while self._send_sent - self._send_granted + n > self._peer_window:
            self._check_sendable()
            self._send_ev.clear()
            if self._send_sent - self._send_granted + n <= self._peer_window:
                return
            await self._send_ev.wait()

    def _check_sendable(self) -> None:
        if self._reset is not None:
            raise StreamError("RESET", self._reset)
        if self._send_fin:
            raise StreamError("SEND_CLOSED")
        if self._t._stopping:
            raise StreamError("CONN_CLOSED", self._t.close_reason or "")

    # receive

    async def recv(self, *, timeout: Optional[float] = None) -> Optional[bytes]:
        """Next verified chunk. b"" is a zero-length FIN chunk; None means the
        peer has finished sending and the buffer is drained."""
        async with self._recv_lock:
            if timeout is None:
                head = await self._next_chunk()
            else:
                try:
                    head = await asyncio.wait_for(self._next_chunk(), timeout)
                except asyncio.TimeoutError:
                    raise StreamError("RECV_TIMEOUT", str(self._sid)) from None
            if head is None:
                return None
            seq, data, fin, mac = head
            try:
                self._signer.verify(self._sid, seq, fin, data, mac)
            except BaseException as exc:
                # Any failure, including BaseException, resets the stream
                # before the exception escapes: never leave it half-consumed.
                self._t._reset_stream(self, "verify_failed", notify=True)
                if isinstance(exc, StreamError):
                    raise StreamError("VERIFY_FAILED", exc.code) from None
                if isinstance(exc, Exception):
                    raise StreamError("VERIFY_FAILED", type(exc).__name__) from None
                raise
            # No await between the peek and here, so the chunk cannot be lost.
            self._buf.popleft()
            self._recv_buffered -= len(data)
            self._touched = time.monotonic()
            self._t._grant(self, len(data))      # credit returns on dequeue only
            self._t._retire_if_done(self)
            return data


    async def _next_chunk(self):
        while True:
            if self._reset is not None:
                raise StreamError("RESET", self._reset)
            if self._buf:
                return self._buf[0]
            if self._remote_fin:
                return None
            if self._t._stopping:
                raise StreamError("CONN_CLOSED", self._t.close_reason or "")
            self._recv_ev.clear()
            if self._buf or self._remote_fin or self._reset is not None:
                continue
            await self._recv_ev.wait()

    # lifecycle

    def cancel(self, reason: str = "cancelled") -> None:
        self._t._reset_stream(self, f"local:{_safe(reason, 64)}", notify=True)

    async def aclose(self, *, fin: bool = True) -> None:
        """Half-close by sending an empty FIN if possible; otherwise cancel."""
        if self._reset is not None or self._t._stopping:
            return
        if fin and not self._send_fin:
            try:
                await self.send(b"", fin=True, timeout=self._t._config.write_timeout)
                return
            except StreamError:
                pass
        if self._reset is None and not self.recv_closed:
            self.cancel("closed")

    async def __aenter__(self) -> "Stream":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is not None:
            self.cancel("aborted")
        else:
            await self.aclose()



class Transport:
    """Use Transport.establish(). The client opens streams; the server accepts."""

    __slots__ = (
        "_config", "_is_client", "_peer_id", "_tag", "_fs", "_signer",
        "_peer_max_frame", "_peer_window", "_peer_max_streams", "_inbound_limit",
        "_streams", "_pending", "_accept_ev", "_next_sid", "_last_peer_sid",
        "_max_sid", "_retired", "_retired_set", "_retired_cap", "_stale_bytes",
        "_cancels", "_credits", "_pong", "_outstanding_pings",
        "_ctl_ev", "_stop_ev", "_stop_code", "_stop_notify", "_stopping",
        "_down", "_closed", "_reader", "_workers", "_supervisor",
    )

    def __init__(
        self, tls: TlsConnection, config: TransportConfig, *, is_client: bool
    ) -> None:
        if not isinstance(config, TransportConfig):
            raise TypeError("config must be a TransportConfig")
        if type(is_client) is not bool:
            raise TypeError("is_client must be bool")

        self._config = config
        self._is_client = is_client
        self._peer_id = tls.peer_id
        self._tag = (
            f"cid={secrets.token_hex(6)} peer={_safe(tls.peer_id)} "
            f"addr={_addr(tls.writer)}"
        )
        self._fs = FrameStream(
            tls.reader, tls.writer,
            write_timeout=config.write_timeout,
        )
        send_ikm, recv_ikm = tls.secrets.for_role(is_client)
        self._signer: StreamSigner = HmacStreamSigner(send_ikm, recv_ikm)

        self._peer_max_frame = MIN_MAX_FRAME
        self._peer_window = 0
        self._peer_max_streams = 0
        self._inbound_limit = HANDSHAKE_MAX_PAYLOAD

        self._streams: dict[int, Stream] = {}      # all live streams
        self._pending: dict[int, Stream] = {}      # subset awaiting accept()
        self._accept_ev = asyncio.Event()
        self._next_sid = 1                         # client only: odd ids
        self._last_peer_sid = 0
        self._max_sid = 0                          # highest id seen, either way

        self._retired_cap = RETIRED_RING_FACTOR * config.max_streams
        self._retired: deque[int] = deque()
        self._retired_set: set[int] = set()
        self._stale_bytes = 0

        self._cancels: dict[int, str] = {}         # pending CANCEL per stream
        self._credits: dict[int, int] = {}         # pending WINDOW_UPDATE per stream
        self._pong: Optional[bytes] = None         # latest PING nonce, one slot
        self._outstanding_pings: deque[bytes] = deque()

        self._ctl_ev = asyncio.Event()
        self._stop_ev = asyncio.Event()
        self._stop_code: Optional[str] = None
        self._stop_notify = False
        self._stopping = False
        self._down = False
        self._closed = asyncio.Event()

        self._reader: Optional[asyncio.Task] = None
        self._workers: list[asyncio.Task] = []
        self._supervisor: Optional[asyncio.Task] = None

    # public API
    @classmethod
    async def establish(
        cls, tls: TlsConnection, config: TransportConfig, *, is_client: bool
    ) -> "Transport":
        try:
            self = cls(tls, config, is_client=is_client)
        except BaseException:
            try:
                tls.writer.close()
            except Exception:
                pass
            raise
        try:
            await asyncio.wait_for(self._handshake(), config.handshake_timeout)
        except asyncio.TimeoutError:
            await self._shutdown("HANDSHAKE_TIMEOUT", notify=False)
            raise TransportError("HANDSHAKE_TIMEOUT", notify=False) from None
        except TransportError as exc:
            await self._shutdown(exc.code, notify=exc.notify)
            raise
        except FrameError as exc:
            await self._shutdown(f"frame:{exc.code}", notify=False)
            raise TransportError(f"frame:{exc.code}", notify=False) from None
        except BaseException:
            await self._shutdown("aborted", notify=False)
            raise

        self._inbound_limit = config.max_frame
        loop = asyncio.get_running_loop()
        try:
            self._reader = loop.create_task(self._reader_loop())
            self._workers = [
                self._reader,
                loop.create_task(self._ping_loop()),
                loop.create_task(self._control_loop()),
                loop.create_task(self._expiry_loop(tls.not_after))
            ]
            self._supervisor = loop.create_task(self._supervise())
        except BaseException:
            await self._shutdown("spawn_failed", notify=False)
            raise

        log.info(
            "transport up %s max_frame=%d window=%d streams=%d",
            self._tag, self._peer_max_frame, self._peer_window,
            self._peer_max_streams,
        )
        return self

    async def open_stream(
        self, kind: str, payload: bytes = b"", *,
        token: bytes = b"", pop: bytes = b"",
    ) -> Stream:
        if not self._is_client:
            raise StreamError("ROLE", "only the client opens streams")
        if self._stopping:
            raise StreamError("CONN_CLOSED", self.close_reason or "")
        if len(self._streams) >= min(self._peer_max_streams, self._config.max_streams):
            raise StreamError("STREAM_LIMIT", str(len(self._streams)))

        sid = self._next_sid
        if sid > MAX_STREAM_ID:
            raise StreamError("STREAM_ID_EXHAUSTED")

        # Build and locally validate. Local misuse is a StreamError, never fatal.
        try:
            frame = make_open_stream(
                stream_id=sid, kind=kind, payload=payload, token=token, pop=pop
            )
        except FrameError as exc:
            raise StreamError(exc.code, exc.detail) from None
        if frame.payload_len > self._peer_max_frame:
            raise StreamError("FRAME_TOO_LARGE_FOR_PEER", str(frame.payload_len))

        self._next_sid = sid + 2
        st = Stream(
            self, sid,
            kind=kind,
            peer_window=self._peer_window,
            window=self._config.stream_window,
            open_body=frame.body,
            open_payload=payload,
            open_token=token,
            open_pop=pop,
            signer=self._signer,
        )
        self._streams[sid] = st
        self._max_sid = max(self._max_sid, sid)

        if not await self._write(frame):
            self._reset_stream(st, "conn_closed", notify=False)
            raise StreamError("CONN_CLOSED", self.close_reason or "")
        return st

    async def accept(self, *, timeout: Optional[float] = None) -> Stream:
        """Next peer-opened stream. Streams reset before they were accepted are
        skipped, so a cancel storm can never block or overflow accept()."""
        if self._is_client:
            raise StreamError("ROLE", "client does not accept streams")
        deadline = (
            
            None if timeout is None
            else asyncio.get_running_loop().time() + timeout
        )
        while True:
            while self._pending:
                sid, st = next(iter(self._pending.items()))
                del self._pending[sid]
                if st._reset is None and self._streams.get(sid) is st:
                    return st
            if self._stopping or self._closed.is_set():
                raise StreamError("CONN_CLOSED", self.close_reason or "")
            self._accept_ev.clear()
            if self._pending or self._stopping:
                continue
            if deadline is None:
                await self._accept_ev.wait()
            else:
                rem = deadline - asyncio.get_running_loop().time()
                if rem <= 0:
                    raise StreamError("ACCEPT_TIMEOUT")
                try:
                    await asyncio.wait_for(self._accept_ev.wait(), rem)
                except asyncio.TimeoutError:
                    raise StreamError("ACCEPT_TIMEOUT") from None

    async def close(self, reason: str = "local") -> None:
        self._request_stop(f"local:{_safe(reason, 64)}", notify=True)
        await self._closed.wait()

    async def wait_closed(self) -> None:
        await self._closed.wait()

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def close_reason(self) -> Optional[str]:
        return self._stop_code

    @property
    def active_streams(self) -> int:
        return len(self._streams)

    async def __aenter__(self) -> "Transport":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close("context_exit" if exc_type is None else "aborted")


    async def _handshake(self) -> None:
        cfg = self._config
        mine = _HELLO.pack(
            PROTOCOL_VERSION, FEATURES, cfg.max_frame,
            cfg.stream_window, cfg.max_streams,
        )
        # Both sides send first, then read: no role ordering dependency.
        if not await self._write(make_session_init(mine)):
            raise TransportError("HANDSHAKE_WRITE", notify=False)

        outcome = await self._fs.recv(
            idle_timeout=self._config.handshake_timeout,
            frame_timeout=self._config.handshake_timeout,
            max_payload=HANDSHAKE_MAX_PAYLOAD,
        )
        if isinstance(outcome, StreamClosed):
            raise TransportError("HANDSHAKE_EOF", outcome.reason, notify=False)

        f = outcome.frame
        if f.type != FrameType.SESSION_INIT:
            raise TransportError("EXPECTED_HELLO", FrameType.name(f.type))
        if f.stream_id or f.flags or f.token or f.pop:
            raise TransportError("BAD_HELLO", "non-empty header fields")
        if len(f.body) != _HELLO.size:
            raise TransportError("BAD_HELLO", f"length {len(f.body)}")

        version, features, max_frame, stream_window, max_streams = _HELLO.unpack(f.body)
        if version != PROTOCOL_VERSION:
            raise TransportError("VERSION", str(version))
        if features != FEATURES:
            raise TransportError("FEATURES", f"0x{features:x}")
        if not MIN_MAX_FRAME <= max_frame <= MAX_FRAME_BYTES:
            raise TransportError("MAX_FRAME", str(max_frame))
        if not MIN_STREAM_WINDOW <= stream_window <= MAX_STREAM_WINDOW:
            raise TransportError("STREAM_WINDOW", str(stream_window))
        if not 1 <= max_streams <= MAX_STREAMS:
            raise TransportError("MAX_STREAMS", str(max_streams))

        self._peer_max_frame = max_frame
        self._peer_window = stream_window
        self._peer_max_streams = max_streams

    async def _expiry_loop(self, not_after):
        deadline =  not_after - self._config.skew
        while True:
            rem = deadline - time.time()
            if rem <= 0:
                self._request_stop("CERT_EXPIRED", notify=True)
                return
            await asyncio.sleep(min(rem, 30.0))

    async def _reader_loop(self) -> None:
        try:
            while not self._stopping:
                outcome = await self._fs.recv(
                    idle_timeout=self._config.idle_timeout,
                    frame_timeout=self._config.frame_timeout,
                    max_payload=lambda: self._inbound_limit,
                )
                if isinstance(outcome, StreamClosed):
                    self._request_stop(f"read:{outcome.reason}", notify=False)
                    return
                self._on_frame(outcome.frame)        # synchronous; never awaits
        except TransportError as exc:
            self._request_stop(exc.code, notify=exc.notify)
        except FrameError as exc:
            self._request_stop(f"frame:{exc.code}", notify=False)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("transport reader crashed %s", self._tag)
            self._request_stop("internal", notify=False)

    async def _ping_loop(self) -> None:
        try:
            while True:
                try:
                    await asyncio.wait_for(
                        self._stop_ev.wait(), self._config.ping_interval
                    )
                except asyncio.TimeoutError:
                    pass
                else:
                    return                           # stop requested
                if self._stopping:
                    return
                self._sweep_idle()
                if len(self._outstanding_pings) >= MAX_OUTSTANDING_PINGS:
                    self._request_stop("PING_TIMEOUT", notify=False)
                    return
                nonce = secrets.token_bytes(PING_NONCE_BYTES)
                self._outstanding_pings.append(nonce)
                if not await self._write(make_ping(nonce=nonce)):
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("transport ping loop crashed %s", self._tag)
            self._request_stop("internal", notify=False)

    async def _control_loop(self) -> None:
        try:
            while True:
                await self._ctl_ev.wait()
                self._ctl_ev.clear()
                if self._stopping:
                    return
                if self._pong is not None:
                    nonce, self._pong = self._pong, None
                    if not await self._write(make_pong(nonce=nonce)):
                        return
                while self._cancels and not self._stopping:
                    sid, reason = next(iter(self._cancels.items()))
                    del self._cancels[sid]
                    if not await self._write(make_cancel(stream_id=sid, reason=reason)):
                        return
                while self._credits and not self._stopping:
                    sid, n = next(iter(self._credits.items()))
                    del self._credits[sid]
                    n = min(n, MAX_WINDOW_CREDIT)
                    if not await self._write(
                        make_window_update(stream_id=sid, credits=n)
                    ):
                        return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("transport control loop crashed %s", self._tag)
            self._request_stop("internal", notify=False)

    async def _supervise(self) -> None:
        try:
            await self._stop_ev.wait()
        except asyncio.CancelledError:
            self._stopping = True
            self._stop_code = self._stop_code or "supervisor_cancelled"
        await self._shutdown(self._stop_code or "stopped", notify=self._stop_notify)

    # inbound dispatch (synchronous: no reordering window)

    def _on_frame(self, f: Frame) -> None:
        t = f.type
        if t == FrameType.STREAM_DATA:
            self._on_stream_data(f)
        elif t == FrameType.WINDOW_UPDATE:
            self._on_window_update(f)
        elif t == FrameType.OPEN_STREAM:
            self._on_open(f)
        elif t == FrameType.CANCEL:
            self._on_cancel(f)
        elif t == FrameType.PING:
            self._pong = f.body                      # coalesce: keep the latest
            self._ctl_ev.set()
        elif t == FrameType.PONG:
            self._on_pong(f)
        elif t == FrameType.CLOSE:
            self._on_close(f)
        elif t == FrameType.ERROR:
            self._on_error(f)
        elif t == FrameType.SESSION_INIT:
            raise TransportError("DUPLICATE_HELLO")
        else:
            # Unreachable: the registry is closed and every registered type is
            # handled above. Kept as a fail-closed backstop.
            raise TransportError("UNHANDLED_FRAME", f"0x{t & 0xFF:02x}")

    def _is_retired(self, sid: int) -> bool:
        return sid in self._retired_set

    def _mark_retired(self, sid: int) -> None:
        if sid in self._retired_set:
            return
        self._retired.append(sid)
        self._retired_set.add(sid)
        while len(self._retired) > self._retired_cap:
            self._retired_set.discard(self._retired.popleft())

    def _tolerate_stale(self, f: Frame, what: str) -> None:
        """A frame for a stream we just retired. Two compliant peers can race
        here, so it is dropped, but the total tolerated volume is capped."""
        self._stale_bytes += f.payload_len
        if self._stale_bytes > MAX_STALE_BYTES:
            raise TransportError("STALE_FLOOD", what)

    def _lookup(self, f: Frame, what: str) -> Optional[Stream]:
        st = self._streams.get(f.stream_id)
        if st is not None:
            return st
        if self._is_retired(f.stream_id):
            self._tolerate_stale(f, what)
            return None
        raise TransportError("UNKNOWN_STREAM", f"{what} sid={f.stream_id}")

    def _on_open(self, f: Frame) -> None:
        if self._is_client:
            raise TransportError("UNEXPECTED_OPEN")
        sid = f.stream_id
        if sid % 2 == 0:
            raise TransportError("BAD_STREAM_ID", f"{sid} is not client-initiated")
        if sid <= self._last_peer_sid:
            raise TransportError("BAD_STREAM_ID", f"{sid} not strictly increasing")
        if len(self._streams) >= self._config.max_streams:
            raise TransportError("STREAM_LIMIT", str(len(self._streams)))

        try:
            kind, payload = parse_open_stream_body(f.body)
        except FrameError as exc:
            raise TransportError("BAD_OPEN", exc.code) from None

        st = Stream(
            self, sid,
            kind=kind,
            peer_window=self._peer_window,
            window=self._config.stream_window,
            open_body=f.body,
            open_payload=payload,
            open_token=f.token,
            open_pop=f.pop,
            signer=self._signer,
        )
        # Bounded by max_streams because _pending is a subset of _streams.
        self._streams[sid] = st
        self._pending[sid] = st
        self._last_peer_sid = sid
        self._max_sid = max(self._max_sid, sid)
        self._accept_ev.set()

    def _on_stream_data(self, f: Frame) -> None:
        st = self._lookup(f, "STREAM_DATA")
        if st is None:
            return                                    # crossed CANCEL/FIN race
        if st._remote_fin:
            raise TransportError("DATA_AFTER_FIN", str(f.stream_id))
        try:
            chunk = parse_stream_data(f)
        except FrameError as exc:
            raise TransportError("BAD_CHUNK", exc.code) from None
        if chunk.seq != st._recv_seq:
            raise TransportError("SEQ", f"{chunk.seq} != {st._recv_seq}")
        if st._recv_buffered + len(chunk.data) > st._window:
            raise TransportError("FLOW_CONTROL", str(f.stream_id))
        
        st._recv_seq += 1
        st._recv_buffered += len(chunk.data)
        st._buf.append((chunk.seq, chunk.data, chunk.fin, chunk.mac))
        st._remote_fin = chunk.fin
        st._touched = time.monotonic()
        st._recv_ev.set()


    def _on_window_update(self, f: Frame) -> None:
        try:
            _, credits = parse_window_update(f)
        except FrameError as exc:
            raise TransportError("BAD_WINDOW_UPDATE", exc.code) from None
        st = self._lookup(f, "WINDOW_UPDATE")
        if st is None:
            return
        if st._send_granted + credits > st._send_sent:
            raise TransportError("CREDIT_OVERRUN", str(f.stream_id))
        st._send_granted += credits
        st._touched = time.monotonic()
        st._send_ev.set()

    def _on_cancel(self, f: Frame) -> None:
        try:
            reason = parse_reason(f.body, field="cancel")
        except FrameError as exc:
            raise TransportError("BAD_CANCEL", exc.code) from None
        st = self._lookup(f, "CANCEL")
        if st is None:
            return
        self._reset_stream(st, f"peer:{reason}", notify=False)

    def _on_pong(self, f: Frame) -> None:
        nonce = f.body
        if nonce not in self._outstanding_pings:
            raise TransportError("UNSOLICITED_PONG", notify=False)
        # Drop this nonce and every older one it supersedes.
        while self._outstanding_pings:
            if self._outstanding_pings.popleft() == nonce:
                break

    def _on_close(self, f: Frame) -> None:
        try:
            reason = parse_reason(f.body, field="close")
        except FrameError as exc:
            raise TransportError("BAD_CLOSE", exc.code, notify=False) from None
        raise TransportError("PEER_CLOSE", reason, notify=False)

    def _on_error(self, f: Frame) -> None:
        # Untrusted. Sanitized, logged, never parsed. Ends the session.
        log.warning(
            "peer ERROR (untrusted) %s: %s",
            self._tag, _safe(f.body.decode("ascii", "replace"), 256),
        )
        raise TransportError("PEER_ERROR", notify=False)

    # state helpers

    def _grant(self, st: Stream, n: int) -> None:
        if n <= 0 or st._reset is not None or self._stopping:
            return
        if self._streams.get(st._sid) is not st:
            return
        total = self._credits.get(st._sid, 0) + n
        self._credits[st._sid] = min(total, MAX_WINDOW_CREDIT)
        self._ctl_ev.set()

    def _retire_if_done(self, st: Stream) -> None:
        if st._send_fin and st._remote_fin and not st._buf and st._reset is None:
            self._forget(st)

    def _forget(self, st: Stream) -> None:
        sid = st._sid
        if self._streams.get(sid) is st:
            del self._streams[sid]
        if self._pending.get(sid) is st:
            del self._pending[sid]
        self._credits.pop(sid, None)
        self._cancels.pop(sid, None)
        self._mark_retired(sid)

    def _reset_stream(self, st: Stream, reason: str, *, notify: bool) -> None:
        if st._reset is not None:
            return
        safe_reason = _safe(reason, 128)
        st._reset = safe_reason
        st._buf.clear()
        st._recv_buffered = 0
        st._send_ev.set()
        st._recv_ev.set()
        was_live = self._streams.get(st._sid) is st
        self._forget(st)
        self._accept_ev.set()                        # unblock accept() scanners
        if notify and was_live and not self._stopping:
            self._cancels[st._sid] = safe_reason
            self._ctl_ev.set()

    def _sweep_idle(self) -> None:
        now = time.monotonic()
        limit = self._config.stream_idle_timeout
        for st in list(self._streams.values()):
            if now - st._touched > limit:
                self._reset_stream(st, "idle_timeout", notify=True)

    def _request_stop(self, code: str, *, notify: bool) -> None:
        if self._stop_code is None:
            self._stop_code = _safe(code)
            self._stop_notify = bool(notify)
        self._stopping = True
        self._stop_ev.set()
        self._ctl_ev.set()
        self._accept_ev.set()
        for st in self._streams.values():            # wake blocked send/recv
            st._send_ev.set()
            st._recv_ev.set()

    async def _write(self, frame: Frame) -> bool:
        try:
            outcome = await self._fs.send(frame, timeout=self._config.write_timeout)
        except FrameError as exc:
            self._request_stop(f"encode:{exc.code}", notify=False)
            return False
        if isinstance(outcome, StreamClosed):
            self._request_stop(f"write:{outcome.reason}", notify=False)
            return False
        return True

    # teardown

    async def _shutdown(self, code: str, *, notify: bool) -> None:
        if self._down:
            await self._closed.wait()
            return
        self._down = True
        try:
            self._request_stop(code, notify=notify)
            code = self._stop_code or code
            notify = self._stop_notify

            # The reader is blocked in a read; cancel it directly.
            if self._reader is not None:
                self._reader.cancel()
            # Other workers observe the stop flag. Give them a short grace
            # period to finish an in-flight write, then cancel.
            others = [t for t in self._workers if t is not self._reader]
            if others:
                _, pending = await asyncio.wait(others, timeout=SHUTDOWN_GRACE)
                for t in pending:
                    t.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
            if self._reader is not None:
                await asyncio.gather(self._reader, return_exceptions=True)

            for st in list(self._streams.values()):
                self._reset_stream(st, f"closed:{code}", notify=False)
            self._streams.clear()
            self._pending.clear()
            self._cancels.clear()
            self._credits.clear()
            self._outstanding_pings.clear()
            self._pong = None
            self._accept_ev.set()

            # Best-effort CLOSE. Skipped if a stalled write still holds the
            # writer lock: shutdown must not inherit a peer's stall.
            if notify and not self._fs.writer.busy and not self._fs.writer.closed:
                try:
                    await self._fs.send(make_close(code), timeout=CLOSE_WRITE_TIMEOUT)
                except Exception:
                    pass
            try:
                await self._fs.close(code)
            except Exception:
                self._fs.writer.abort(code)
            log.info("transport closed %s code=%s", self._tag, _safe(code))
        finally:
            # Unconditional: close()/wait_closed() can never hang.
            self._closed.set()


