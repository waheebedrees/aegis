"""One bidirectional, flow-controlled, MAC-verified stream.

Deadline contract:
  * A deadline bounds only the PRE-COMMIT phase (lock + credit / lock + buffer).
    Timing out there leaves the stream exactly as it was (scope=CALLER, retryable).
  * Once a chunk is committed, delivery is governed by the connection's
    write_timeout; a stall there is connection-fatal, never silent.
Fail-closed:
  * Signer failure on send  -> nothing committed, CALLER error.
  * Verify failure on recv  -> stream reset UNAUTHENTICATED before raising.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import hmac
import struct
import time
from collections import deque
from typing import Optional, Protocol, TypeGuard

from libs.transport.frame import (
    FIXED_OVERHEAD,
    MAX_CHUNK_BYTES,
    MAX_SEQ,
    STREAM_MAC_BYTES,
    Frame,
    StreamChunk,
    make_stream_data,
)
from libs.transport.stream.deadline import Deadline, effective_deadline
from libs.transport.stream.errors import (
    AegisError,
    ProtocolViolation,
    Scope,
    Status,
    StreamError,
    safe_text,
    TransportError,
)
from libs.transport.stream._signer import StreamSigner

__all__ = ["MAC_LEN", "StreamState", "Stream"]

MAC_LEN = STREAM_MAC_BYTES


class StreamState(enum.Enum):
    OPEN = "open"
    HALF_CLOSED_LOCAL = "half_closed_local"
    HALF_CLOSED_REMOTE = "half_closed_remote"
    CLOSED = "closed"
    RESET = "reset"


class StreamHost(Protocol):
    @property
    def peer_id(self) -> str: ...
    @property
    def channel_binding(self) -> bytes: ...
    @property
    def peer_max_frame(self) -> int: ...
    @property
    def op_timeout(self) -> float: ...
    @property
    def is_stopping(self) -> bool: ...
    @property
    def close_error(self) -> Optional[AegisError]: ...

    async def write_frame(self, frame: Frame) -> bool: ...
    def grant_window(self, stream: "Stream", credits: int) -> None: ...
    def on_progress(self, stream: "Stream") -> None: ...
    def reset(self, stream: "Stream", status: Status, reason: str, *, notify: bool) -> None: ...
    def request_stop(self, err: TransportError) -> None: ...


def is_int(value: object) -> TypeGuard[int]:
    return type(value) is int


def is_bytes(value: object) -> TypeGuard[bytes]:
    return type(value) is bytes


def is_bool(value: object) -> TypeGuard[bool]:
    return type(value) is bool


class Stream:
    """One bidirectional flow-controlled, authenticated stream."""

    __slots__ = (
        "_host",
        "_stream_id",
        "_kind",
        "_peer_window",
        "_window",
        "_open_payload",
        "_open_token",
        "_open_pop",
        "_signer",
        "_send_seq",
        "_send_sent",
        "_send_granted",
        "_send_fin",
        "_send_lock",
        "_send_ev",
        "_recv_seq",
        "_recv_buffered",
        "_buf",
        "_remote_fin",
        "_recv_lock",
        "_recv_ev",
        "_reset_status",
        "_reset_reason",
        "_touched",
    )

    def __init__(
        self,
        host: StreamHost,
        stream_id: int,
        *,
        kind: str,
        peer_window: int,
        window: int,
        open_payload: bytes,
        open_token: bytes,
        open_pop: bytes,
        signer: StreamSigner,
    ) -> None:

        self._host = host
        self._stream_id = stream_id
        self._kind = kind
        self._peer_window = peer_window

        self._window = window
        self._open_payload = open_payload
        self._open_token = open_token
        self._open_pop = open_pop
        self._signer = signer

        self._send_seq = 0
        self._send_sent = 0
        self._send_granted = 0
        self._recv_seq = 0
        self._recv_buffered = 0
        self._send_fin = False
        self._remote_fin = False

        self._send_lock = asyncio.Lock()
        self._send_ev = asyncio.Event()
        self._recv_lock = asyncio.Lock()
        self._recv_ev = asyncio.Event()
        self._reset_status: Optional[Status] = None
        self._reset_reason: Optional[str] = None

        self._touched = time.monotonic()
        self._buf: deque[tuple[int, bytes, bool, bytes]] = deque()

    @property
    def state(self) -> StreamState:
        if self._reset_status is not None:
            return StreamState.RESET
        lc, rc = self._send_fin, (self._remote_fin and not self._buf)
        if lc and rc:
            return StreamState.CLOSED
        if lc:
            return StreamState.HALF_CLOSED_LOCAL
        if rc:
            return StreamState.HALF_CLOSED_REMOTE
        return StreamState.OPEN

    @property
    def status(self) -> Status:
        return Status.OK if self._reset_status is None else self._reset_status

    @property
    def reset_reason(self) -> Optional[str]:
        return self._reset_reason

    @property
    def is_reset(self) -> bool:
        return self._reset_status is not None

    @property
    def send_closed(self) -> bool:
        return self._send_fin or self.is_reset

    @property
    def recv_closed(self) -> bool:
        return (self._remote_fin and not self._buf) or self.is_reset

    @property
    def is_done(self) -> bool:
        return self.state is StreamState.CLOSED

    def is_idle(self, now: float, limit: float) -> bool:
        return (now - self._touched) > limit

    def __repr__(self) -> str:
        return f"<Stream sid={self._stream_id} kind={self._kind!r} state={self.state.value} status={self.status.name}>"

    async def _await_credit(self, n: int) -> None:
        while self._send_sent - self._send_granted + n > self._peer_window:
            self._check_sendable()
            self._send_ev.clear()
            if self._send_sent - self._send_granted + n <= self._peer_window:
                return
            await self._send_ev.wait()

    async def _next_chunk(self) -> Optional[tuple[int, bytes, bool, bytes]]:
        while True:
            if self._reset_status is not None:
                raise StreamError(self._reset_status, "RESET", self._reset_reason or "")
            if self._buf:
                # return self._buf[0]
                return self._buf.popleft()  # atomic within the wait_for task

            if self._remote_fin:
                return None
            if self._host.is_stopping:
                raise self._conn_closed()
            self._recv_ev.clear()
            if self._buf or self._remote_fin or self._reset_status is not None:
                continue
            await self._recv_ev.wait()

    def _check_sendable(self) -> None:
        if self._reset_status is not None:
            raise StreamError(self._reset_status, "RESET", self._reset_reason or "")
        if self._send_fin:
            raise StreamError(Status.FAILED_PRECONDITION, "SEND_CLOSED", scope=Scope.CALLER)
        if self._host.is_stopping:
            raise self._conn_closed()

    def _conn_closed(self) -> StreamError:
        err = self._host.close_error
        if err is None:
            return StreamError(Status.UNAVAILABLE, "CONN_CLOSED")
        if err.status is Status.OK:                       # fix #6
            return StreamError(Status.CANCELLED, "CONN_CLOSED", "local close")
        return StreamError(err.status, "CONN_CLOSED", str(err))

 
    async def send(
        self,
        data: bytes,
        *,
        fin: bool = False,
        deadline: Optional[Deadline] = None,
        timeout: Optional[float] = None,
    ) -> None:

        d = effective_deadline(deadline, timeout, default=self._host.op_timeout, op="send")

        if not is_bytes(data):
            raise StreamError(
                Status.INVALID_ARGUMENT,
                "BAD_DATA",
                type(data).__name__,
                scope=Scope.CALLER,
            )
        if not is_bool(fin):
            raise StreamError(
                Status.INVALID_ARGUMENT,
                "BAD_FIN",
                type(fin).__name__,
                scope=Scope.CALLER,
            )
        if len(data) > MAX_CHUNK_BYTES:
            raise StreamError(
                Status.OUT_OF_RANGE,
                "CHUNK_TOO_LARGE",
                str(len(data)),
                scope=Scope.CALLER,
            )
        if not data and not fin:
            raise StreamError(Status.INVALID_ARGUMENT, "EMPTY_CHUNK", scope=Scope.CALLER)
        if len(data) > self._peer_window:
            raise StreamError(
                Status.OUT_OF_RANGE,
                "CHUNK_EXCEEDS_WINDOW",
                str(len(data)),
                scope=Scope.CALLER,
            )
        if FIXED_OVERHEAD + MAC_LEN + 8 + len(data) > self._host.peer_max_frame:
            raise StreamError(
                Status.OUT_OF_RANGE,
                "FRAME_TOO_LARGE_FOR_PEER",
                str(len(data)),
                scope=Scope.CALLER,
            )

        await d.run(self._send_lock.acquire(), "send:lock")
        try:
            self._check_sendable()
            await d.run(self._await_credit(len(data)), "send:credit")
            self._check_sendable()
            d.check("send")
            seq = self._send_seq
            if seq > MAX_SEQ:
                raise StreamError(
                    Status.RESOURCE_EXHAUSTED,
                    "SEQ_EXHAUSTED",
                    str(self._stream_id),
                    scope=Scope.CALLER,
                )
            try:
                mac = self._signer.sign(self._stream_id, seq, fin, data)
            except AegisError:
                raise
            except Exception as exc:
                raise StreamError(
                    Status.INTERNAL,
                    "SIGN_FAILED",
                    type(exc).__name__,
                    scope=Scope.CALLER,
                ) from None
            if type(mac) is not bytes or len(mac) != MAC_LEN:
                raise StreamError(Status.INTERNAL, "BAD_MAC", scope=Scope.CALLER)

            frame = make_stream_data(
                stream_id=self._stream_id, seq=seq, data=data, mac=mac, fin=fin
            )

            # ── commit point ── nothing above mutated state
            self._send_seq = seq + 1
            self._send_sent += len(data)
            if fin:
                self._send_fin = True
            self._touched = time.monotonic()

            try:
                written = await self._host.write_frame(frame)
            except asyncio.CancelledError:
                self._host.request_stop(
                    TransportError(Status.ABORTED, "local:cancelled_during_write", notify=False)
                )
                raise
            if not written:
                raise self._conn_closed()
            self._host.on_progress(self)

        finally:
            self._send_lock.release()

    async def recv(
        self,
        *,
        deadline: Optional[Deadline] = None,
        timeout: Optional[float] = None,
    ) -> Optional[bytes]:
        """Next verified chunk; None once the peer FINs and the buffer drains."""

        d = effective_deadline(deadline, timeout, default=self._host.op_timeout, op="recv")
        await d.run(self._recv_lock.acquire(), "recv:lock")
        try:
            head = await d.run(self._next_chunk(), "recv:wait")
            if head is None:
                return None

            seq, data, fin, mac = head
            try:
                mac = self._signer.verify(self._stream_id, seq, fin, data, mac)
            except BaseException as exc:
                self._host.reset(self, Status.UNAUTHENTICATED, "verify_failed", notify=True)
                if isinstance(exc, AegisError):
                    raise StreamError(Status.UNAUTHENTICATED, "VERIFY_FAILED", exc.code) from None
                if isinstance(exc, Exception):
                    raise StreamError(
                        Status.UNAUTHENTICATED,
                        "VERIFY_FAILED",
                        type(exc).__name__,
                    ) from None
                raise

            # ── commit point ──
            if self._reset_status is None:
                self._recv_buffered -= len(data)
            self._touched = time.monotonic()
            self._host.grant_window(self, len(data))
            self._host.on_progress(self)
            return data

        finally:
            self._recv_lock.release()

    async def aclose(
        self,
        *,
        fin: bool = True,
        deadline: Optional[Deadline] = None,
        timeout: Optional[float] = None,
    ) -> None:
        if self.is_reset or self._host.is_stopping:
            return
        if fin and not self._send_fin:
            try:
                await self.send(b"", fin=True, deadline=deadline, timeout=timeout)
                return
            except AegisError:
                pass  # fall through: fail-closed cancel
        if not self.is_reset and not self.recv_closed:
            self.cancel("closed")

    async def __aenter__(self) -> "Stream":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.cancel("aborted")
        else:
            await self.aclose()

    def cancel(self, reason: str = "cancelled") -> None:
        self._host.reset(
            self,
            Status.CANCELLED,
            f"local:{safe_text(reason, 64)}",
            notify=True,
        )


    def deliver(self, chunk: StreamChunk) -> None:
        if self._remote_fin:
            raise ProtocolViolation("DATA_AFTER_FIN", str(self._stream_id))
        if chunk.seq != self._recv_seq:
            raise ProtocolViolation("SEQ", f"{chunk.seq} != {self._recv_seq}")
        if self._recv_buffered + len(chunk.data) > self._window:
            raise ProtocolViolation("FLOW_CONTROL", str(self._stream_id), status=Status.RESOURCE_EXHAUSTED)
        self._recv_seq += 1
        self._recv_buffered += len(chunk.data)
        self._buf.append((chunk.seq, chunk.data, chunk.fin, chunk.mac))
        self._remote_fin = chunk.fin
        self._touched = time.monotonic()
        self._recv_ev.set()
        # fix #5 — peer may have FINed and buffer is now empty; if we
        # already FINed the stream is done and must be retired here,
        # not only on the next user-initiated send/recv.
        self._host.on_progress(self)

    def apply_credit(self, credits: int) -> None:
        if self._send_granted + credits > self._send_sent:
            raise ProtocolViolation("CREDIT_OVERRUN", str(self._stream_id))
        self._send_granted += credits
        self._touched = time.monotonic()
        self._send_ev.set()

    def mark_reset(self, status: Status, reason: str) -> Optional[str]:
        if self._reset_status is not None:
            return None
        self._reset_status = Status(status)
        self._reset_reason = safe_text(reason, 128)
        self._buf.clear()
        self._recv_buffered = 0
        self._send_ev.set()
        self._recv_ev.set()
        return self._reset_reason

    def wake(self) -> None:
        self._send_ev.set()
        self._recv_ev.set()
