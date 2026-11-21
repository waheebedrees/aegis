"""Channel — mode-enforced, deadline-aware messaging over one L4 Stream.

Wires to the transport via the ByteStream protocol, which L4 Stream
satisfies structurally. Callers get codec-aware send(obj) / recv() -> Any
and a single RemoteError for peer-terminated calls. See spec §2.1 for
mode contract, §3.4 for backpressure (byte-level only in M1).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, NoReturn, Optional, Protocol, runtime_checkable
from libs.proto.tlv import TLVEntry
from libs.proto.codec import Codec
from libs.proto.hello import Mode, ChannelHello

from libs.proto.envelope import (
    EndFrame,
    Envelope,
    MsgType,
    HeaderTag,
    decode_envelope,
    encode_envelope,
    make_end_headers,
)
from libs.proto.fragment import (
    DEFAULT_MAX_FRAGMENTS,
    DEFAULT_MAX_MESSAGE_BYTES,
    Fragmenter,
    Message,
    Reassembler,
)
from libs.proto.status import (
    ChannelError,
    ProtocolError,
    RemoteError,
    Status,
    malformed,
    map_exception,
)
from libs.transport.stream_session import StreamError, Transport

__all__ = [
    "ByteStream",
    "Channel",
    "ChannelConfig",
    "open_channel",
    "accept_channel",
]


class _EOF:
    __slots__ = ()

    def __repr__(self) -> str:
        return "EOF"


EOF: Any = _EOF()
EOFType = _EOF


@runtime_checkable
class ByteStream(Protocol):
    """Structural interface satisfied by libs.transport.stream_session.Stream."""

    @property
    def peer_id(self) -> str: ...
    @property
    def kind(self) -> str: ...
    @property
    def open_payload(self) -> bytes: ...
    async def send(
        self, data: bytes, *, fin: bool = False, timeout: float | None = None
    ) -> None: ...
    async def recv(self, *, timeout: float | None = None) -> bytes | None: ...
    def cancel(self, reason: str = "cancelled") -> None: ...


@dataclass(frozen=True, slots=True)
class ChannelConfig:
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_fragments: int = DEFAULT_MAX_FRAGMENTS
    max_chunk_bytes: int = 60 * 1024
    terminal_fin_timeout: float = 5.0

    def __post_init__(self) -> None:
        from libs.proto.envelope import MAX_ENVELOPE_BYTES, PREFIX_LEN

        if not 1 <= self.max_message_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_message_bytes")
        if not 1 <= self.max_fragments <= 65536:
            raise ValueError("max_fragments")
        if not PREFIX_LEN + 64 <= self.max_chunk_bytes <= MAX_ENVELOPE_BYTES:
            raise ValueError("max_chunk_bytes")
        if not (
            isinstance(self.terminal_fin_timeout, (int, float))
            and 0 < self.terminal_fin_timeout < 60
        ):
            raise ValueError("terminal_fin_timeout")


def _mode_limits(mode: Mode, role: str) -> tuple[int | None, int | None]:
    """(send_limit, recv_limit). None = unbounded, 0 = forbidden.

    DATAGRAM (spec §2.1): initiator sends N messages and receives no DATA
    reply (only END). Acceptor sends no DATA (only END) and receives N.
    send_limit=0 does not block end(), which goes through a separate path.
    """
    if role == "initiator":
        return {
            Mode.UNARY: (1, 1),
            Mode.CLIENT_STREAM: (None, 1),
            Mode.SERVER_STREAM: (1, None),
            Mode.BIDI: (None, None),
            Mode.DATAGRAM: (None, 0),
        }[mode]
    return {
        Mode.UNARY: (1, 1),
        Mode.CLIENT_STREAM: (1, None),
        Mode.SERVER_STREAM: (None, 1),
        Mode.BIDI: (None, None),
        Mode.DATAGRAM: (0, None),
    }[mode]


def _deadline_from(hello: ChannelHello) -> Optional[float]:
    return time.monotonic() + hello.deadline_ms / 1000.0 if hello.deadline_ms else None


class Channel:
    """One channel. Thread-safe for concurrent send/recv across tasks."""

    __slots__ = (
        "_stream",
        "_hello",
        "_codec",
        "_role",
        "_config",
        "_deadline",
        "_send_limit",
        "_recv_limit",
        "_send_count",
        "_recv_count",
        "_local_ended",
        "_remote_ended",
        "_pending_terminal",
        "_terminal_error",
        "_fragmenter",
        "_reassembler",
        "_send_lock",
        "_recv_lock",
        "_send_schema",
        "_recv_schema",
        "_peer_trailers",
    )

    def __init__(
        self,
        stream: ByteStream,
        hello: ChannelHello,
        codec: Codec,
        *,
        role: str,
        config: ChannelConfig | None = None,
        deadline_at: float | None = None,
        send_schema_id: str = "",
        recv_schema_id: str = "",
    ) -> None:
        if role not in ("initiator", "acceptor"):
            raise ValueError("role must be 'initiator' or 'acceptor'")
        if not isinstance(hello, ChannelHello):
            raise TypeError("hello must be a ChannelHello")
        self._stream = stream
        self._hello = hello
        self._codec = codec
        self._role = role
        self._config = config or ChannelConfig()
        self._deadline = deadline_at
        self._send_schema = send_schema_id or hello.schema_id
        self._recv_schema = recv_schema_id or hello.schema_id
        self._fragmenter = Fragmenter(self._config.max_chunk_bytes)
        self._reassembler = Reassembler(
            self._config.max_message_bytes,
            self._config.max_fragments,
        )
        self._send_limit, self._recv_limit = _mode_limits(hello.mode, role)
        self._send_count = 0
        self._recv_count = 0
        self._local_ended = False
        self._remote_ended = False
        self._pending_terminal: tuple | None = None
        self._terminal_error: ChannelError | None = None
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._peer_trailers: dict[int, bytes] = {}

    @property
    def peer_id(self) -> str:
        return self._stream.peer_id

    @property
    def kind(self) -> str:
        return self._stream.kind

    @property
    def hello(self) -> ChannelHello:
        return self._hello

    @property
    def mode(self) -> Mode:
        return self._hello.mode

    @property
    def method(self) -> str:
        return self._hello.method

    @property
    def role(self) -> str:
        return self._role

    @property
    def deadline(self) -> float | None:
        return self._deadline

    @property
    def send_closed(self) -> bool:
        return self._local_ended or self._terminal_error is not None

    @property
    def recv_closed(self) -> bool:
        return self._remote_ended or self._terminal_error is not None

    @property
    def peer_trailers(self) -> dict[int, bytes]:
        """App-defined trailers from the peer's END. Empty after ERROR or before end."""
        return self._peer_trailers

    def remaining_s(self) -> float | None:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    # ── internals ─────────────────────────────────────────────────────

    def _check_live(self) -> None:
        if self._terminal_error is not None:
            raise self._terminal_error
        if self._local_ended and self._remote_ended:
            raise ProtocolError(Status.CANCELLED, "channel closed")

    def _eff_timeout(self, user: float | None) -> float | None:
        if self._deadline is None:
            return user
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            self._abort(ProtocolError(Status.DEADLINE_EXCEEDED, "channel deadline"))
        if user is None:
            return remaining
        return min(user, remaining)

    def _abort(self, error: ChannelError) -> NoReturn:
        if self._terminal_error is None:
            self._terminal_error = error
        self._local_ended = True
        self._remote_ended = True
        try:
            self._stream.cancel(error.status.name.lower()[:64])
        except Exception:
            pass
        raise error

    @classmethod
    async def open_channel(
        cls,
        transport: Transport,
        kind: str,
        hello: ChannelHello,
        codec: Codec,
        token: bytes = b"",
        pop: bytes = b"",
        *,
        config: ChannelConfig | None = None,
        send_schema_id: str = "",
        recv_schema_id: str = "",
    ) -> Channel:
        deadline_at = _deadline_from(hello)
        try:
            payload = hello.encode()
            st = await transport.open_stream(kind, payload, token=token, pop=pop)
        except StreamError as exc:
            raise map_exception(exc) from None
        return Channel(
            st,
            hello,
            codec,
            role="initiator",
            config=config,
            deadline_at=deadline_at,
            send_schema_id=send_schema_id,
            recv_schema_id=recv_schema_id,
        )

    async def _send_envelope(
        self,
        env: Envelope,
        *,
        fin: bool,
        timeout: float | None,
    ) -> None:
        raw = encode_envelope(env)
        effective = self._eff_timeout(timeout)
        try:
            await self._stream.send(raw, fin=fin, timeout=effective)
        except ChannelError:
            raise
        except Exception as exc:
            mapped = map_exception(exc)
            self._terminal_error = mapped
            self._local_ended = True
            self._remote_ended = True
            raise mapped from None

    async def send(
        self,
        value: Any,
        *,
        headers: tuple[TLVEntry, ...] = (),
        end: bool = False,
        timeout: float | None = None,
    ) -> None:
        self._check_live()
        if self._local_ended:
            raise ProtocolError(Status.FAILED_PRECONDITION, "send side closed")
        if self._send_limit == 0:
            raise ProtocolError(
                Status.FAILED_PRECONDITION,
                f"send not allowed in {self._hello.mode.name}",
            )
        if self._send_limit is not None and self._send_count >= self._send_limit:
            raise ProtocolError(
                Status.FAILED_PRECONDITION,
                f"{self._hello.mode.name} allows {self._send_limit} send(s)",
            )

        # Per-message SCHEMA_ID override: honour it for codec, strip from wire
        # headers (the codec already attached it via the schema_id arg, or the
        # channel default applies).
        schema = self._send_schema
        filtered: list[TLVEntry] = []
        for h in headers:
            if h.tag == int(HeaderTag.SCHEMA_ID):
                schema = h.value.decode("ascii")
            else:
                filtered.append(h)

        raw = self._codec.encode(value, schema_id=schema)
        if type(raw) is not bytes:
            raise ProtocolError(Status.INVALID_ARGUMENT, "codec returned non-bytes")
        if len(raw) > self._config.max_message_bytes:
            raise ProtocolError(Status.RESOURCE_EXHAUSTED, f"message {len(raw)}B")

        async with self._send_lock:
            self._check_live()
            if self._local_ended:
                raise ProtocolError(Status.FAILED_PRECONDITION, "send side closed")
            try:
                for env in self._fragmenter.fragment(raw, tuple(filtered)):
                    await self._send_envelope(env, fin=False, timeout=timeout)
            except ChannelError:
                raise
            except BaseException:
                self._abort(ProtocolError(Status.ABORTED, "send aborted"))
            self._send_count += 1
            if end:
                await self._send_end_locked(
                    Status.OK, "", detail=b"", trailers=None, timeout=timeout
                )

    async def recv(self, *, timeout: float | None = None) -> Message:
        msg = await self.recv_message(timeout=timeout)
        if msg is None:
            return EOF

        # Honour a peer-supplied SCHEMA_ID for this message.
        schema = self._recv_schema
        for h in msg.headers:
            if h.tag == int(HeaderTag.SCHEMA_ID):
                try:
                    schema = h.value.decode("ascii")
                except UnicodeDecodeError:
                    self._abort(ProtocolError(Status.MALFORMED, "bad SCHEMA_ID"))
                break
        return self._codec.decode(msg.data, schema_id=schema)

    async def recv_honour(self, *, timeout: float | None = None) -> Message:
        msg = await self.recv_message(timeout=timeout)
        if msg is None:
            return EOF

        # Honour a peer-supplied SCHEMA_ID for this message.
        schema = self._recv_schema
        for h in msg.headers:
            if h.tag == int(HeaderTag.SCHEMA_ID):
                try:
                    schema = h.value.decode("ascii")
                except UnicodeDecodeError:
                    self._abort(ProtocolError(Status.MALFORMED, "bad SCHEMA_ID"))
                break
        value = self._codec.decode(msg.data, schema_id=schema)
        return Message(value, msg.headers)

    async def recv_message(
        self,
        *,
        timeout: float | None = None,
    ) -> Message | None:
        self._check_live()
        if self._remote_ended:
            if self._terminal_error is not None:
                raise self._terminal_error
            return None
        async with self._recv_lock:
            return await self._next(timeout)

    async def _next(self, user_timeout: float | None) -> Message | None:

        while True:
            if self._pending_terminal is not None:
                tail = await self._stream.recv(timeout=self._eff_timeout(user_timeout))
                if tail is not None:
                    self._abort(ProtocolError(Status.MALFORMED, "data after terminal envelope"))
                status, message, retry, detail, trailers = (
                    self._pending_terminal
                )  # ← include trailers
                self._pending_terminal = None
                self._remote_ended = True
                self._peer_trailers = trailers
                if status is not Status.OK:
                    raise RemoteError(
                        status,
                        message,
                        retry_after_ms=retry,
                        error_detail=detail,
                    )
                return None

            raw = None
            effective = self._eff_timeout(user_timeout)
            try:
                raw = await self._stream.recv(timeout=effective)
            except ChannelError:
                raise
            except Exception as exc:
                mapped = map_exception(exc)
                if mapped.status is Status.DEADLINE_EXCEEDED and (
                    self._deadline is None or time.monotonic() < self._deadline
                ):
                    raise mapped from None
                self._abort(mapped)

            if raw is None:
                self._abort(ProtocolError(Status.MALFORMED, "transport FIN without END/ERROR"))

            try:
                env = decode_envelope(raw)
            except ProtocolError as exc:
                self._abort(exc)
            if env.type is MsgType.DATA:
                if self._recv_limit is not None and self._recv_count >= self._recv_limit:
                    self._abort(
                        ProtocolError(
                            Status.MALFORMED,
                            f"{self._hello.mode.name} allows {self._recv_limit} recv(s)",
                        )
                    )
                try:
                    msg = self._reassembler.feed(env)
                except ProtocolError as exc:
                    self._abort(exc)
                if msg is not None:
                    self._recv_count += 1
                    return msg
                continue
            if env.type in (MsgType.END, MsgType.ERROR):
                try:
                    self._reassembler.check_no_partial(env.type.name)
                    ef = EndFrame.parse(env.type is MsgType.ERROR, env.headers)
                except ProtocolError as exc:
                    self._abort(exc)
                if ef.status is Status.OK and self._recv_limit == 1 and self._recv_count != 1:
                    self._abort(
                        ProtocolError(
                            Status.MALFORMED,
                            f"expected 1 message before END(OK), got {self._recv_count}",
                        )
                    )
                self._pending_terminal = (
                    ef.status,
                    ef.message,
                    ef.retry_after_ms,
                    ef.detail,
                    dict(ef.trailers),
                )
                continue
            if env.type in (MsgType.CREDIT, MsgType.CONTROL):
                continue
            self._abort(
                ProtocolError(
                    Status.MALFORMED,
                    f"unexpected envelope type {env.type.name}",
                )
            )

    async def end(
        self,
        status: Status = Status.OK,
        message: str = "",
        *,
        detail: bytes = b"",
        trailers: dict[int, bytes] | None = None,
        timeout: float | None = None,
    ) -> None:
        self._check_live()
        async with self._send_lock:
            await self._send_end_locked(
                status,
                message,
                detail=detail,
                trailers=trailers,
                timeout=timeout,
            )

    async def _send_end_locked(
        self,
        status: Status,
        message: str,
        *,
        detail: bytes,
        trailers: dict[int, bytes] | None,
        timeout: float | None,
    ) -> None:
        if self._local_ended:
            return
        if (
            status is Status.OK
            and self._send_limit is not None
            and self._send_count != self._send_limit
        ):
            raise ProtocolError(
                Status.FAILED_PRECONDITION,
                f"cannot end {self._hello.mode.name} with OK after "
                f"{self._send_count}/{self._send_limit} sends",
            )
        env = Envelope(
            MsgType.END,
            headers=make_end_headers(status, message, detail=detail, trailers=trailers),
        )
        self._local_ended = True
        await self._send_envelope(env, fin=True, timeout=timeout)

    async def fail(
        self,
        status: Status,
        message: str = "",
        *,
        detail: bytes = b"",
        retry_after_ms: int = 0,
        timeout: float | None = None,
    ) -> None:
        if status is Status.OK:
            raise ProtocolError(Status.INVALID_ARGUMENT, "fail requires non-OK status")
        if self._local_ended:
            return
        async with self._send_lock:
            if self._local_ended:
                return
            env = Envelope(
                MsgType.ERROR,
                headers=make_end_headers(
                    status,
                    message,
                    detail=detail,
                    retry_after_ms=retry_after_ms,
                ),
            )
            self._local_ended = True
            await self._send_envelope(env, fin=True, timeout=timeout)

    def cancel(self, reason: str = "cancelled") -> None:
        try:
            self._stream.cancel(reason[:64])
        except Exception:
            pass
        self._local_ended = True
        self._remote_ended = True

    async def aclose(self) -> None:
        """End cleanly, drain the peer's terminal, cancel only if needed."""
        if self._local_ended and self._remote_ended:
            return
        if not self._local_ended and self._terminal_error is None:
            try:
                await self.end(Status.OK)
            except Exception:
                pass
        if not self._remote_ended and self._terminal_error is None:
            try:
                await self._drain_terminal(total_timeout=self._config.terminal_fin_timeout)
            except Exception:
                pass
        if not self._local_ended or not self._remote_ended:
            try:
                self._stream.cancel("closed")
            except Exception:
                pass

    async def _drain_terminal(self, *, total_timeout: float) -> None:
        if self._recv_lock.locked():
            return
        deadline = time.monotonic() + total_timeout
        async with self._recv_lock:
            while not self._remote_ended:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                try:
                    raw = await self._stream.recv(timeout=min(remaining, 0.5))
                except Exception:
                    return
                if raw is None:
                    self._remote_ended = True
                    return
                try:
                    env = decode_envelope(raw)
                except ProtocolError:
                    return
                if env.type in (MsgType.END, MsgType.ERROR):
                    self._remote_ended = True
                    return

    async def __aenter__(self) -> Channel:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.cancel("aborted")
        else:
            await self.aclose()

    def __aiter__(self) -> AsyncIterator[Any]:
        return self

    async def __anext__(self) -> Message:
        value = await self.recv()
        if value is EOF:
            raise StopAsyncIteration
        return value


async def open_channel(
    stream: ByteStream,
    hello: ChannelHello,
    codec: Codec,
    *,
    config: ChannelConfig | None = None,
    deadline_at: float | None = None,
    send_schema_id: str = "",
    recv_schema_id: str = "",
) -> Channel:
    return Channel(
        stream,
        hello,
        codec,
        role="initiator",
        config=config,
        deadline_at=deadline_at,
        send_schema_id=send_schema_id,
        recv_schema_id=recv_schema_id,
    )


async def accept_channel(
    stream: ByteStream,
    codec: Codec,
    *,
    config: ChannelConfig | None = None,
    deadline_at: float | None = None,
    send_schema_id: str = "",
    recv_schema_id: str = "",
) -> Channel:
    try:
        hello = ChannelHello.decode(stream.open_payload)
    except ProtocolError:
        try:
            stream.cancel("bad_hello")
        except Exception:
            pass
        raise
    return Channel(
        stream,
        hello,
        codec,
        role="acceptor",
        config=config,
        deadline_at=deadline_at,
        send_schema_id=send_schema_id,
        recv_schema_id=recv_schema_id,
    )
