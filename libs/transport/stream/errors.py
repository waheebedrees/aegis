from __future__ import annotations


from typing import Optional
import enum

_MAX_WIRE = 0xFFFF


class Status(enum.IntEnum):
    OK = 0
    CANCELLED = 1
    UNKNOWN = 2
    INVALID_ARGUMENT = 3
    DEADLINE_EXCEEDED = 4
    NOT_FOUND = 5
    ALREADY_EXISTS = 6
    PERMISSION_DENIED = 7
    RESOURCE_EXHAUSTED = 8
    FAILED_PRECONDITION = 9
    ABORTED = 10
    OUT_OF_RANGE = 11
    UNIMPLEMENTED = 12
    INTERNAL = 13
    UNAVAILABLE = 14
    DATA_LOSS = 15
    UNAUTHENTICATED = 16


_RETRYABLE = frozenset(
    {
        Status.UNAVAILABLE,
        Status.RESOURCE_EXHAUSTED,
        Status.ABORTED,
        Status.DEADLINE_EXCEEDED,
    }
)


class Scope(enum.Enum):
    CALLER = "caller"  # local misuse; no state changed
    STREAM = "stream"  # stream reset; connection still up
    CONNECTION = "connection"  # connection closing / closed


class AegisError(Exception):
    __slots__ = ("status", "code", "detail", "scope", "retryable", "notify")

    def __init__(
        self,
        status: Status,
        code: str,
        detail: str = "",
        *,
        scope: Scope,
        retryable: Optional[bool] = None,
        notify: bool = False,
    ) -> None:
        self.status = Status(status)
        self.code = safe_text(code, 48)
        self.detail = safe_text(detail, 256)
        self.scope = scope
        self.retryable = (self.status in _RETRYABLE) if retryable is None else bool(retryable)
        self.notify = bool(notify)
        super().__init__(str(self))

    def __str__(self) -> str:
        base = f"{self.status.name}/{self.code}"
        return f"{base}: {self.detail}" if self.detail else base

    @property
    def fatal(self) -> bool:
        return self.scope is Scope.CONNECTION


class StreamError(AegisError):
    """Stream-scoped or caller error. Connection stays up."""

    def __init__(
        self,
        status: Status,
        code: str,
        detail: str = "",
        *,
        scope: Scope = Scope.STREAM,
        retryable: Optional[bool] = None,
    ) -> None:
        if scope is Scope.CONNECTION:
            raise ValueError("StreamError cannot have CONNECTION scope")
        super().__init__(status, code, detail, scope=scope, retryable=retryable)


class TransportError(AegisError):
    """Connection-fatal. `notify` says whether a CLOSE frame may be sent."""

    def __init__(
        self,
        status: Status,
        code: str,
        detail: str = "",
        *,
        notify: bool = True,
        retryable: Optional[bool] = None,
    ) -> None:
        super().__init__(
            status,
            code,
            detail,
            scope=Scope.CONNECTION,
            retryable=retryable,
            notify=notify,
        )


class ProtocolViolation(TransportError):
    """Behaviour a compliant peer can never produce."""

    def __init__(
        self,
        code: str,
        detail: str = "",
        *,
        status: Status = Status.FAILED_PRECONDITION,
        notify: bool = True,
    ) -> None:
        super().__init__(status, code, detail, notify=notify, retryable=False)


class DeadlineExceeded(AegisError):
    def __init__(self, op: str, *, scope: Scope = Scope.CALLER) -> None:
        super().__init__(
            Status.DEADLINE_EXCEEDED,
            "DEADLINE",
            op,
            scope=scope,
            retryable=True,
        )


def close_reason(err: AegisError) -> str:
    """Wire-safe CLOSE/CANCEL reason: STATUS/code."""
    return safe_text(f"{err.status.name}/{err.code}", 128)


def safe_text(text: object, limit: int = 128) -> str:
    return "".join(c if " " <= c <= "~" else "_" for c in str(text)[:limit])


def status_from_wire(code: int) -> tuple[Status, int]:
    """Map a u16 from the wire. Unknown non-zero codes degrade to INTERNAL;
    the raw value is returned so it can be surfaced, never lost."""
    if type(code) is not int or not 0 <= code <= _MAX_WIRE:
        raise ValueError("status code out of range")
    try:
        return Status(code), code
    except ValueError:
        return Status.INTERNAL, code


def stream_error(
    status: Status,
    code: str,
    detail: str = "",
    *,
    scope: Scope = Scope.STREAM,
    retryable: Optional[bool] = None,
) -> StreamError:
    return StreamError(status, code, detail, scope=scope, retryable=retryable)


def transport_error(
    status: Status,
    code: str,
    detail: str = "",
    *,
    notify: bool = True,
    retryable: Optional[bool] = None,
) -> TransportError:
    return TransportError(status, code, detail, notify=notify, retryable=retryable)


_CODE_STATUS: dict[str, Status] = {
    "MAC_MISMATCH": Status.UNAUTHENTICATED,
    "VERIFY_FAILED": Status.UNAUTHENTICATED,
    "BAD_SIGNER": Status.INVALID_ARGUMENT,
    "BAD_DATA": Status.INVALID_ARGUMENT,
    "BAD_FIN": Status.INVALID_ARGUMENT,
    "BAD_MAC": Status.INVALID_ARGUMENT,
    "BAD_KIND": Status.INVALID_ARGUMENT,
    "CHUNK_TOO_LARGE": Status.INVALID_ARGUMENT,
    "CHUNK_EXCEEDS_WINDOW": Status.INVALID_ARGUMENT,
    "FRAME_TOO_LARGE_FOR_PEER": Status.INVALID_ARGUMENT,
    "EMPTY_CHUNK": Status.INVALID_ARGUMENT,
    "STREAM_LIMIT": Status.RESOURCE_EXHAUSTED,
    "FLOW_CONTROL": Status.RESOURCE_EXHAUSTED,
    "STALE_FLOOD": Status.RESOURCE_EXHAUSTED,
    "STREAM_ID_EXHAUSTED": Status.RESOURCE_EXHAUSTED,
    "SEQ": Status.DATA_LOSS,
    "SEQ_EXHAUSTED": Status.DATA_LOSS,
    # "DATA_AFTER_FIN": Status.PROTOCOL_ERROR,
    # "CREDIT_OVERRUN": Status.PROTOCOL_ERROR,
    # "UNKNOWN_STREAM": Status.PROTOCOL_ERROR,
    # "BAD_STREAM_ID": Status.PROTOCOL_ERROR,
    # "UNEXPECTED_OPEN": Status.PROTOCOL_ERROR,
    # "DUPLICATE_HELLO": Status.PROTOCOL_ERROR,
    # "UNHANDLED_FRAME": Status.UNIMPLEMENTED,
    # "UNSOLICITED_PONG": Status.PROTOCOL_ERROR,
    "RESET": Status.CANCELLED,
    "SEND_CLOSED": Status.FAILED_PRECONDITION,
    "ALREADY_ACTIVE": Status.FAILED_PRECONDITION,
    "ROLE": Status.PERMISSION_DENIED,
    "CONN_CLOSED": Status.UNAVAILABLE,
    "PEER_CLOSE": Status.UNAVAILABLE,
    "PEER_ERROR": Status.UNAVAILABLE,
    "HANDSHAKE_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "PING_TIMEOUT": Status.DEADLINE_EXCEEDED,
    "CERT_EXPIRED": Status.UNAUTHENTICATED,
}
