"""Stream table, ID parity, pending accepts, tombstones. No I/O."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Callable, Optional

from libs.transport.frame import (
    MAX_STREAM_ID,
    Frame,
    FrameError,
    make_open_stream,
    parse_open_stream_body,
    parse_reason,
    parse_stream_data,
    parse_window_update,
)
from libs.transport.stream.deadline import Deadline, effective_deadline
from libs.transport.stream.errors import ProtocolViolation, Scope, Status, StreamError, safe_text
from libs.transport.stream.stream import Stream, StreamHost, StreamSigner

log = logging.getLogger(__name__)

__all__ = [
    "MAX_STALE_BYTES",
    "RETIRED_RING_FACTOR",
    "StreamAuthorizer",
    "Denied",
    "StreamMultiplexer",
]

MAX_STALE_BYTES = 8 * 1024 * 1024
RETIRED_RING_FACTOR = 8

StreamAuthorizer = Callable[[int, str, bytes, bytes, bytes], Optional[tuple[Status, str]]]

Denied = tuple[int, Status, str]


class StreamMultiplexer:
    __slots__ = (
        "_host",
        "_signer",
        "_is_client",
        "_bidi",
        "_max_streams",
        "_local_window",
        "_authorizer",
        "_streams",
        "_pending",
        "_accept_ev",
        "_next_sid",
        "_last_peer_sid",
        "_retired_cap",
        "_retired",
        "_retired_set",
        "_stale_bytes",
    )

    def __init__(
        self,
        host: StreamHost,
        signer: StreamSigner,
        *,
        is_client: bool,
        max_streams: int,
        local_window: int,
        authorizer: Optional[StreamAuthorizer] = None,
    ) -> None:

        self._host = host
        self._signer = signer
        self._is_client = is_client
        self._bidi = False
        self._max_streams = max_streams
        self._local_window = local_window
        self._authorizer = authorizer
        self._streams: dict[int, Stream] = {}
        self._pending: dict[int, Stream] = {}
        self._accept_ev = asyncio.Event()
        self._next_sid = 1 if is_client else 2  # odd = client, even = server
        self._last_peer_sid = 0
        self._retired_cap = RETIRED_RING_FACTOR * max_streams
        self._retired: deque[int] = deque()
        self._retired_set: set[int] = set()
        self._stale_bytes = 0

    def set_bidi(self, on: bool) -> None:
        self._bidi = bool(on)

    @property
    def active(self) -> int:
        return len(self._streams)

    @property
    def can_initiate(self) -> bool:
        return self._is_client or self._bidi

    @property
    def can_accept(self) -> bool:
        return (not self._is_client) or self._bidi

    def allocate(
        self,
        kind: str,
        payload: bytes,
        *,
        token: bytes,
        pop: bytes,
        peer_max_streams: int,
        peer_window: int,
    ) -> tuple[Stream, Frame]:
        if not self.can_initiate:
            raise StreamError(
                Status.FAILED_PRECONDITION,
                "ROLE",
                "cannot initiate streams",
                scope=Scope.CALLER,
            )
        if len(self._streams) >= min(peer_max_streams, self._max_streams):
            raise StreamError(
                Status.RESOURCE_EXHAUSTED,
                "STREAM_LIMIT",
                str(len(self._streams)),
                scope=Scope.CALLER,
            )
        sid = self._next_sid
        if sid > MAX_STREAM_ID:
            raise StreamError(
                Status.RESOURCE_EXHAUSTED,
                "STREAM_ID_EXHAUSTED",
                scope=Scope.CALLER,
                retryable=False,
            )
        try:
            frame = make_open_stream(
                stream_id=sid, kind=kind, payload=payload, token=token, pop=pop
            )
        except FrameError as exc:
            raise StreamError(
                Status.INVALID_ARGUMENT,
                exc.code,
                exc.detail,
                scope=Scope.CALLER,
            ) from None
        if frame.payload_len > self._host.peer_max_frame:
            raise StreamError(
                Status.OUT_OF_RANGE,
                "FRAME_TOO_LARGE_FOR_PEER",
                str(frame.payload_len),
                scope=Scope.CALLER,
            )

        self._next_sid = sid + 2
        st = Stream(
            self._host,
            sid,
            kind=kind,
            peer_window=peer_window,
            window=self._local_window,
            open_payload=payload,
            open_token=token,
            open_pop=pop,
            signer=self._signer,
        )
        self._streams[sid] = st
        return st, frame

    async def accept(
        self,
        *,
        deadline: Optional[Deadline] = None,
        timeout: Optional[float] = None,
    ) -> Stream:
        if not self.can_accept:
            raise StreamError(
                Status.FAILED_PRECONDITION,
                "ROLE",
                "accept not negotiated",
                scope=Scope.CALLER,
            )
        d = effective_deadline(deadline, timeout, default=self._host.op_timeout, op="accept")
        while True:
            while self._pending:
                sid, st = next(iter(self._pending.items()))
                del self._pending[sid]
                if not st.is_reset and self._streams.get(sid) is st:
                    return st
            if self._host.is_stopping:
                err = self._host.close_error
                raise StreamError(
                    err.status if err else Status.UNAVAILABLE,
                    "CONN_CLOSED",
                    str(err or ""),
                )
            self._accept_ev.clear()
            if self._pending or self._host.is_stopping:
                continue
            await d.run(self._accept_ev.wait(), "accept")

    def on_open(self, frame: Frame, *, peer_window: int) -> Optional[Denied]:
        if not self.can_accept:
            raise ProtocolViolation("UNEXPECTED_OPEN")
        sid = frame.stream_id
        if sid % 2 != (0 if self._is_client else 1):
            raise ProtocolViolation("BAD_STREAM_ID", f"{sid} wrong parity")
        if sid <= self._last_peer_sid:
            raise ProtocolViolation("BAD_STREAM_ID", f"{sid} not increasing")
        if len(self._streams) >= self._max_streams:
            raise ProtocolViolation(
                "STREAM_LIMIT",
                str(len(self._streams)),
                status=Status.RESOURCE_EXHAUSTED,
            )
        try:
            kind, payload = parse_open_stream_body(frame.body)
        except FrameError as exc:
            raise ProtocolViolation("BAD_OPEN", exc.code, status=Status.INVALID_ARGUMENT) from None
        self._last_peer_sid = sid

        if self._authorizer is not None:
            try:
                verdict = self._authorizer(sid, kind, payload, frame.token, frame.pop)
            except Exception as exc:  # fail-closed: deny
                log.warning(
                    "stream authorizer raised %s; denying sid=%d",
                    type(exc).__name__,
                    sid,
                )
                verdict = (Status.PERMISSION_DENIED, "authorizer_error")
            if verdict is not None:
                status, reason = verdict
                self._mark_retired(sid)
                return sid, Status(status), safe_text(reason, 96)

        st = Stream(
            self._host,
            sid,
            kind=kind,
            peer_window=peer_window,
            window=self._local_window,
            open_payload=payload,
            open_token=frame.token,
            open_pop=frame.pop,
            signer=self._signer,
        )
        self._streams[sid] = st
        self._pending[sid] = st
        self._accept_ev.set()
        return None

    def on_stream_data(self, frame: Frame) -> None:
        st = self._lookup(frame, "STREAM_DATA")
        if st is None:
            return
        try:
            chunk = parse_stream_data(frame)
        except FrameError as exc:
            raise ProtocolViolation("BAD_CHUNK", exc.code, status=Status.INVALID_ARGUMENT) from None
        st.deliver(chunk)

    def on_window_update(self, frame: Frame) -> None:
        try:
            _, credits = parse_window_update(frame)
        except FrameError as exc:
            raise ProtocolViolation(
                "BAD_WINDOW_UPDATE", exc.code, status=Status.INVALID_ARGUMENT
            ) from None
        st = self._lookup(frame, "WINDOW_UPDATE")
        if st is not None:
            st.apply_credit(credits)

    def on_cancel(self, frame: Frame) -> Optional[tuple[Stream, str]]:
        try:
            reason = parse_reason(frame.body, field="cancel")
        except FrameError as exc:
            raise ProtocolViolation(
                "BAD_CANCEL", exc.code, status=Status.INVALID_ARGUMENT
            ) from None
        st = self._lookup(frame, "CANCEL")
        return None if st is None else (st, f"peer:{reason}")

    def _lookup(self, frame: Frame, what: str) -> Optional[Stream]:
        st = self._streams.get(frame.stream_id)
        if st is not None:
            return st
        if frame.stream_id in self._retired_set:
            self._stale_bytes += frame.payload_len
            if self._stale_bytes > MAX_STALE_BYTES:
                raise ProtocolViolation("STALE_FLOOD", what, status=Status.RESOURCE_EXHAUSTED)
            return None
        raise ProtocolViolation(
            "UNKNOWN_STREAM",
            f"{what} sid={frame.stream_id}",
            status=Status.NOT_FOUND,
        )

    def _mark_retired(self, sid: int) -> None:
        if sid in self._retired_set:
            return
        self._retired.append(sid)
        self._retired_set.add(sid)
        while len(self._retired) > self._retired_cap:
            self._retired_set.discard(self._retired.popleft())

    def forget(self, st: Stream) -> bool:
        sid = st._stream_id
        was_live = self._streams.get(sid) is st
        if was_live:
            del self._streams[sid]
        if self._pending.get(sid) is st:
            del self._pending[sid]
        self._mark_retired(sid)
        self._accept_ev.set()
        return was_live

    def retire_if_done(self, st: Stream) -> bool:
        if st.is_done:
            self.forget(st)
            return True
        return False

    def idle(self, limit: float) -> list[Stream]:
        now = time.monotonic()
        return [st for st in self._streams.values() if st.is_idle(now, limit)]

    def wake_all(self) -> None:
        self._accept_ev.set()
        for st in self._streams.values():
            st.wake()

    def clear(self, status: Status, reason: str) -> None:
        for st in self._streams.values():
            st.mark_reset(status, reason)
        self._streams.clear()
        self._pending.clear()
        self._accept_ev.set()
