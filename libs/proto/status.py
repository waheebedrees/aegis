"""Canonical status codes (spec §3.3). Closed and append-only.

Wire form: u16. Codes 0..18 are defined; anything else is MALFORMED.
The retryability classification is authoritative — a caller may key
its retry policy on it without parsing detail strings.
"""

from __future__ import annotations

import asyncio
from enum import IntEnum

from libs.transport.stream_session import StreamError, TransportError

__all__ = [
    "Status",
    "RETRYABLE",
    "IDEMPOTENT_ONLY_RETRY",
    "ChannelError",
    "ProtocolError",
    "RemoteError",
    "malformed",
    "map_stream_error",
]


class Status(IntEnum):
    OK = 0
    CANCELLED = 1
    INVALID_ARGUMENT = 2
    DEADLINE_EXCEEDED = 3
    NOT_FOUND = 4
    ALREADY_EXISTS = 5
    PERMISSION_DENIED = 6
    RESOURCE_EXHAUSTED = 7
    FAILED_PRECONDITION = 8
    ABORTED = 9
    OUT_OF_RANGE = 10
    UNIMPLEMENTED = 11
    INTERNAL = 12
    UNAVAILABLE = 13
    DATA_LOSS = 14
    UNAUTHENTICATED = 15
    UNSUPPORTED_MEDIA = 16
    MALFORMED = 17
    POLICY_DENIED = 18

    @classmethod
    def valid(cls, value: object) -> bool:
        return type(value) is int and 0 <= value <= cls.POLICY_DENIED

    def is_retryable(self, *, idempotent: bool = False) -> bool:
        if self in RETRYABLE:
            return True
        return idempotent and self in IDEMPOTENT_ONLY_RETRY


RETRYABLE = frozenset(
    {
        Status.UNAVAILABLE,
        Status.RESOURCE_EXHAUSTED,
        Status.ABORTED,
        Status.DEADLINE_EXCEEDED,
    }
)
IDEMPOTENT_ONLY_RETRY = frozenset({Status.INTERNAL, Status.DATA_LOSS})


def _printable(text: object, limit: int = 256) -> str:
    return "".join(c if 0x20 <= ord(c) <= 0x7E else "_" for c in str(text)[:limit])


class ChannelError(Exception):
    """Base for all channel-scoped failures. The connection stays up."""

    __slots__ = ("status", "detail")

    def __init__(self, status: Status, detail: str = "") -> None:
        if not isinstance(status, Status):
            raise TypeError("status must be a Status")
        safe = _printable(detail)
        super().__init__(f"{status.name}: {safe}" if safe else status.name)
        self.status = status
        self.detail = safe


class ProtocolError(ChannelError):
    """Local misuse or peer violation of the channel contract."""


class RemoteError(ChannelError):
    """Peer terminated the channel with a non-OK status."""

    __slots__ = ("retry_after_ms", "error_detail")

    def __init__(
        self,
        status: Status,
        detail: str = "",
        *,
        retry_after_ms: int = 0,
        error_detail: bytes = b"",
    ) -> None:
        super().__init__(status, detail)
        self.retry_after_ms = retry_after_ms
        self.error_detail = error_detail


class LocalError(ProtocolError):
    """Failure caused by local state or local misuse. Never counted against a peer."""


def map_transport_error(exc: TransportError) -> ProtocolError:
    if exc.code in _MALFORMED:
        st = Status.MALFORMED
    else:
        st = _TRANSPORT.get(exc.code, Status.UNAVAILABLE)
    return ProtocolError(st, f"transport:{exc.code}")


def map_exception(exc: BaseException) -> ChannelError:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return ProtocolError(Status.DEADLINE_EXCEEDED, "timeout")
    if isinstance(exc, ChannelError):
        return exc
    if isinstance(exc, StreamError):
        return map_stream_error(exc)
    if isinstance(exc, TransportError):
        return map_transport_error(exc)
    return ProtocolError(Status.INTERNAL, type(exc).__name__)  # never leak str(exc)


def malformed(message: str) -> ProtocolError:
    """Shorthand for the most common error path."""
    return ProtocolError(Status.MALFORMED, message)


def map_stream_error(exc: StreamError) -> ProtocolError:
    detail = f"stream:{exc.code}"
    if exc.code in _LOCAL:
        return LocalError(_LOCAL[exc.code], detail)
    return ProtocolError(_PEER.get(exc.code, Status.UNAVAILABLE), detail)


def error(
    status: Status,
    detail: str = "",
) -> ProtocolError:
    return ProtocolError(status, detail)


_STREAM_MAP = {
    "RECV_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "CREDIT_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "RESET": Status.CANCELLED,
    "CONN_CLOSED": Status.UNAVAILABLE,
    "SEND_CLOSED": Status.FAILED_PRECONDITION,
    "EMPTY_CHUNK": Status.INVALID_ARGUMENT,
    "BAD_DATA": Status.INVALID_ARGUMENT,
    "CHUNK_TOO_LARGE": Status.OUT_OF_RANGE,
    "CHUNK_EXCEEDS_WINDOW": Status.OUT_OF_RANGE,
    "FRAME_TOO_LARGE_FOR_PEER": Status.OUT_OF_RANGE,
    "VERIFY_FAILED": Status.DATA_LOSS,
    "MAC_MISMATCH": Status.DATA_LOSS,
    "SIGN_FAILED": Status.INTERNAL,
    "BAD_MAC": Status.INTERNAL,
}


_LOCAL = {
    "STREAM_LIMIT": Status.RESOURCE_EXHAUSTED,
    "STREAM_ID_EXHAUSTED": Status.RESOURCE_EXHAUSTED,
    "SEQ_EXHAUSTED": Status.RESOURCE_EXHAUSTED,
    "FRAME_TOO_LARGE_FOR_PEER": Status.RESOURCE_EXHAUSTED,
    "CHUNK_EXCEEDS_WINDOW": Status.RESOURCE_EXHAUSTED,
    "ROLE": Status.FAILED_PRECONDITION,
    "SEND_CLOSED": Status.FAILED_PRECONDITION,
    "ALREADY_ACTIVE": Status.FAILED_PRECONDITION,
    "CHUNK_TOO_LARGE": Status.INVALID_ARGUMENT,
    "EMPTY_CHUNK": Status.INVALID_ARGUMENT,
    "BAD_DATA": Status.INVALID_ARGUMENT,
    "BAD_FIN": Status.INVALID_ARGUMENT,
    "BAD_KIND": Status.INVALID_ARGUMENT,
    "SIGN_FAILED": Status.INTERNAL,
    "BAD_SIGNER": Status.INTERNAL,
    "BAD_MAC": Status.INTERNAL,
}
_PEER = {
    "CONN_CLOSED": Status.UNAVAILABLE,
    "RESET": Status.CANCELLED,
    "RECV_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "CREDIT_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "ACCEPT_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "VERIFY_FAILED": Status.UNAUTHENTICATED,
    "MAC_MISMATCH": Status.UNAUTHENTICATED,
}
_TRANSPORT = {
    "CERT_EXPIRED": Status.UNAUTHENTICATED,
    "STREAM_LIMIT": Status.RESOURCE_EXHAUSTED,
    "STALE_FLOOD": Status.RESOURCE_EXHAUSTED,
    "UNHANDLED_FRAME": Status.INTERNAL,
    "RESET": Status.CANCELLED,
}
_MALFORMED = {
    "FLOW_CONTROL",
    "SEQ",
    "DATA_AFTER_FIN",
    "CREDIT_OVERRUN",
    "BAD_STREAM_ID",
    "BAD_OPEN",
    "BAD_CHUNK",
    "BAD_WINDOW_UPDATE",
    "BAD_CANCEL",
    "BAD_CLOSE",
    "BAD_HELLO",
    "EXPECTED_HELLO",
    "DUPLICATE_HELLO",
    "UNKNOWN_EXTENSION",
}


_STREAM_STATUS: dict[str, Status] = {
    "SEND_CLOSED": Status.FAILED_PRECONDITION,
    "RECV_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "CONN_CLOSED": Status.UNAVAILABLE,
    "RESET": Status.ABORTED,
    "MAC_MISMATCH": Status.UNAUTHENTICATED,
    "VERIFY_FAILED": Status.UNAUTHENTICATED,
    "SEQ": Status.MALFORMED,
    "FLOW_CONTROL": Status.RESOURCE_EXHAUSTED,
    "CHUNK_TOO_LARGE": Status.RESOURCE_EXHAUSTED,
    "CHUNK_EXCEEDS_WINDOW": Status.RESOURCE_EXHAUSTED,
    "FRAME_TOO_LARGE_FOR_PEER": Status.RESOURCE_EXHAUSTED,
    "CREDIT_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "SEQ_EXHAUSTED": Status.INTERNAL,
    "SIGN_FAILED": Status.INTERNAL,
    "BAD_MAC": Status.INTERNAL,
    "BAD_SIGNER": Status.INTERNAL,
    "ALREADY_ACTIVE": Status.FAILED_PRECONDITION,
    "BAD_DATA": Status.INVALID_ARGUMENT,
    "BAD_FIN": Status.INVALID_ARGUMENT,
    "EMPTY_CHUNK": Status.INVALID_ARGUMENT,
}

_TRANSPORT_STATUS: dict[str, Status] = {
    "HANDSHAKE_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "HANDSHAKE_EOF": Status.UNAVAILABLE,
    "HANDSHAKE_WRITE": Status.UNAVAILABLE,
    "EXPECTED_HELLO": Status.FAILED_PRECONDITION,
    "BAD_HELLO": Status.MALFORMED,
    "VERSION": Status.FAILED_PRECONDITION,
    "FEATURES": Status.FAILED_PRECONDITION,
    "FEATURES_MISSING": Status.FAILED_PRECONDITION,
    "MAX_FRAME": Status.FAILED_PRECONDITION,
    "STREAM_WINDOW": Status.FAILED_PRECONDITION,
    "MAX_STREAMS": Status.FAILED_PRECONDITION,
    "CERT_EXPIRED": Status.UNAUTHENTICATED,
    "PEER_CLOSE": Status.UNAVAILABLE,
    "PEER_ERROR": Status.INTERNAL,
    "PING_TIMEOUT": Status.UNAVAILABLE,
    "UNEXPECTED_OPEN": Status.FAILED_PRECONDITION,
    "DUPLICATE_HELLO": Status.MALFORMED,
    "UNKNOWN_STREAM": Status.MALFORMED,
}


def from_stream_error(code: str) -> Status:
    if code.startswith("local:"):
        code = code[len("local:") :]
    return _STREAM_STATUS.get(code, Status.INTERNAL)


def from_transport_error(code: str) -> Status:
    if code.startswith("frame:"):
        code = code[len("frame:") :]
    if code.startswith("local:"):
        code = code[len("local:") :]
    return _TRANSPORT_STATUS.get(code, Status.INTERNAL)


def from_capchain_code(code) -> Status:

    from libs.capchain import capchain as cc

    table = {
        cc.Code.TOKEN_EXPIRED: Status.UNAUTHENTICATED,
        cc.Code.TOKEN_NOT_YET_VALID: Status.UNAUTHENTICATED,
        cc.Code.POP_MISMATCH: Status.UNAUTHENTICATED,
        cc.Code.POP_BAD_SIGNATURE: Status.UNAUTHENTICATED,
        cc.Code.POP_STALE: Status.UNAUTHENTICATED,
        cc.Code.POP_BINDING: Status.UNAUTHENTICATED,
        cc.Code.CB_MISMATCH: Status.UNAUTHENTICATED,
        cc.Code.TOKEN_SIGNATURE: Status.UNAUTHENTICATED,
        cc.Code.UNKNOWN_ISSUER: Status.UNAUTHENTICATED,
        cc.Code.POP_REQUIRED: Status.UNAUTHENTICATED,
        cc.Code.NOT_ENROLLED: Status.UNAUTHENTICATED,
        cc.Code.TOKEN_MALFORMED: Status.MALFORMED,
        cc.Code.TOKEN_TOO_LARGE: Status.MALFORMED,
        cc.Code.POP_MALFORMED: Status.MALFORMED,
        cc.Code.CHAIN_BROKEN: Status.MALFORMED,
        cc.Code.CONTEXT_DRIFT: Status.MALFORMED,
        cc.Code.SCOPE_MISMATCH: Status.PERMISSION_DENIED,
        cc.Code.SCOPE_WIDENED: Status.PERMISSION_DENIED,
        cc.Code.POLICY_DENIED: Status.PERMISSION_DENIED,
        cc.Code.WRONG_HOLDER: Status.PERMISSION_DENIED,
        cc.Code.WRONG_AUDIENCE: Status.PERMISSION_DENIED,
        cc.Code.REVOKED: Status.PERMISSION_DENIED,
        cc.Code.WRONG_SESSION: Status.FAILED_PRECONDITION,
        cc.Code.TOO_DEEP: Status.FAILED_PRECONDITION,
        cc.Code.WRONG_TASK: Status.FAILED_PRECONDITION,
        cc.Code.MODEL_MISMATCH: Status.FAILED_PRECONDITION,
        cc.Code.BUDGET_EXHAUSTED: Status.RESOURCE_EXHAUSTED,
        cc.Code.INTERNAL: Status.INTERNAL,
        cc.Code.EVIDENCE_BROKEN: Status.INTERNAL,
        cc.Code.REPLAY: Status.ABORTED,
        cc.Code.STATE_UNAVAILABLE: Status.UNAVAILABLE,
    }
    return table.get(code, Status.INTERNAL)
