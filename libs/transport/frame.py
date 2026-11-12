"""libs/transport/stream/frame.py — bounded length-prefixed framing (wire v4).

Wire layout:

    offset   size  field
    0        4     payload_len   (u32 BE; excludes these 4 bytes)
    4        1     type          (u8)
    5        2     flags         (u16 BE)
    7        4     stream_id     (u32 BE, 0..0x7FFFFFFF; 0 = session)
    11       4     token_len     (u32 BE)
    15       N     token
    15+N     4     pop_len       (u32 BE)
    19+N     M     pop
    19+N+M   K     body

    PROLOGUE_LEN   = 11  (type + flags + stream_id + token_len)
    FIXED_OVERHEAD = 15  (PROLOGUE_LEN + pop_len)
    payload_len    = 15 + N + M + K

Invariants:
  * Frame types come solely from a locally configured, immutable FrameRegistry.
    Unknown types are rejected after 15 bytes, before any payload is read.
  * Per-type limits (flags, stream_id, token_len, payload_len) are enforced
    after the 15-byte header and before reading the payload tail, so the
    largest pre-validation allocation is 15 bytes.
  * Once the 4-byte length prefix is consumed, ANY error or cancellation marks
    the FrameReader permanently closed. There is no resynchronization.
  * Two deadlines: `idle_timeout` bounds the wait for the first byte of a
    frame; `frame_timeout` bounds the remainder once the prefix is consumed.
    A peer therefore cannot hold a read slot open by trickling bytes, and a
    legitimately idle connection is not penalized for large frames.
  * Cancelling FrameWriter during drain() does not desynchronize the stream:
    writer.write() already queued the complete frame synchronously.
"""

from __future__ import annotations

import asyncio
import enum
import math
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import (
    Callable,
    Iterable,
    Mapping,
    Optional,
    Protocol,
    TypeGuard,
    Union,
)

__all__ = [
    # Wire constants
    "WIRE_VERSION",
    "HEADER_LEN",
    "PROLOGUE_LEN",
    "FIXED_OVERHEAD",
    "MAX_FRAME_BYTES",
    "MAX_TOKEN_BYTES",
    "MAX_POP_BYTES",
    "MAX_BODY_BYTES",
    "MAX_STREAM_ID",
    "MAX_CHUNK_BYTES",
    "STREAM_MAC_BYTES",
    "MAX_WINDOW_CREDIT",
    "MAX_SEQ",
    "PING_NONCE_BYTES",
    "MAX_REASON_BYTES",
    "OPEN_MAX_TOKEN",
    "OPEN_MAX_POP",
    "OPEN_MAX_BODY",
    "HELLO_MAX_BODY",
    "WRITE_TIMEOUT",
    "CLOSE_TIMEOUT",
    # Types & registry
    "FrameType",
    "Flags",
    "StreamIdRule",
    "Frame",
    "FrameSpec",
    "FrameRegistry",
    "DEFAULT_REGISTRY",
    # Errors
    "FrameError",
    "StreamCloseError",
    # Constructors & parsers
    "StreamChunk",
    "make_session_init",
    "make_close",
    "make_error",
    "make_open_stream",
    "parse_open_stream",
    "parse_open_stream_body",
    "make_stream_data",
    "parse_stream_data",
    "make_window_update",
    "parse_window_update",
    "make_cancel",
    "parse_reason",
    "make_ping",
    "make_pong",
    "fits",
    # Codec
    "encode_frame",
    "decode_frame",
    # Async I/O
    "ByteReader",
    "ByteWriter",
    "FrameReceived",
    "StreamClosed",
    "FrameWritten",
    "StreamCloseSucceeded",
    "StreamCloseFailed",
    "RecvOutcome",
    "WriteOutcome",
    "CloseOutcome",
    "FrameReader",
    "FrameWriter",
    "FrameStream",
]

WIRE_VERSION = 4

# ───────────────────────── wire limits ─────────────────────────
# Global caps are deliberately as tight as the tightest real user, so a
# mis-specified FrameSpec cannot widen the attack surface past these.

HEADER_LEN = 4
_TYPE_LEN = 1
_FLAGS_LEN = 2
_STREAM_ID_LEN = 4
_LEN_LEN = 4
PROLOGUE_LEN = _TYPE_LEN + _FLAGS_LEN + _STREAM_ID_LEN + _LEN_LEN   # 11
FIXED_OVERHEAD = PROLOGUE_LEN + _LEN_LEN                            # 15

MAX_CHUNK_BYTES = 256 * 1024          # keep in sync with capchain/streams.py
STREAM_MAC_BYTES = 32                 # HMAC-SHA256
MAX_FRAME_BYTES = FIXED_OVERHEAD + 8 + MAX_CHUNK_BYTES + STREAM_MAC_BYTES
MAX_BODY_BYTES = MAX_FRAME_BYTES - FIXED_OVERHEAD

OPEN_MAX_TOKEN = 4 * 1024             # was 32 KiB: bounds per-stream retention
OPEN_MAX_POP = 1 * 1024
OPEN_MAX_BODY = 4 * 1024
HELLO_MAX_BODY = 64
MAX_REASON_BYTES = 128
PING_NONCE_BYTES = 8

MAX_TOKEN_BYTES = OPEN_MAX_TOKEN
MAX_POP_BYTES = OPEN_MAX_POP

MAX_STREAM_ID = 0x7FFFFFFF
MAX_WINDOW_CREDIT = 0x7FFFFFFF
MAX_SEQ = (1 << 63) - 1

WRITE_TIMEOUT = 30.0
CLOSE_TIMEOUT = 5.0


DATA_MAX_BODY  = 4 * 1024          # matches OPEN_MAX_BODY
DATA_MAX_TOKEN = OPEN_MAX_TOKEN    # 4 KiB
DATA_MAX_POP   = OPEN_MAX_POP      # 1 KiB


_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")
_U64 = struct.Struct(">Q")
_PROLOGUE = struct.Struct(">BHII")     # type, flags, stream_id, token_len

assert _PROLOGUE.size == PROLOGUE_LEN

_MAX_ERR_CODE = 48
_ERR_LEN = struct.Struct(">H")


# ───────────────────────── helpers ─────────────────────────

def _is_int(value: object) -> TypeGuard[int]:
    return type(value) is int


def _is_bytes(value: object) -> bool:
    return type(value) is bytes


def _safe_ascii(text: str, limit: int) -> bytes:
    """Lossy-map to printable ASCII minus quote/backslash, then truncate."""
    if not isinstance(text, str):
        raise FrameError("BAD_TEXT", type(text).__name__)
    return "".join(
        c if 0x20 <= ord(c) < 0x7F and c not in ('"', "\\") else "_"
        for c in text
    )[:limit].encode("ascii")


def _is_printable_ascii(raw: bytes) -> bool:
    return all(0x20 <= b <= 0x7E for b in raw)


class FrameError(Exception):
    """Framing violation, unregistered frame type, or caller misuse."""

    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class StreamCloseError(Exception):
    """Raised from FrameStream.__aexit__ when close fails with no active error."""

    __slots__ = ("reason",)

    def __init__(self, reason: str) -> None:
        super().__init__(f"stream close failed: {reason}")
        self.reason = reason


# ───────────────────────── types & registry ─────────────────────────

class StreamIdRule(enum.Enum):
    ZERO = "zero"        # session-level (stream_id == 0)
    NONZERO = "nonzero"  # stream-level  (1 <= stream_id <= MAX_STREAM_ID)


class Flags:
    NONE = 0x0000
    FIN = 0x0001
    ALL = FIN


@dataclass(frozen=True, slots=True)
class Frame:
    """Immutable wire frame. Per-type constraints live in FrameSpec."""

    type: int
    stream_id: int = 0
    flags: int = Flags.NONE
    token: bytes = b""
    pop: bytes = b""
    body: bytes = b""

    def __post_init__(self) -> None:
        if not _is_int(self.type) or not 1 <= self.type <= 0xFF:
            raise FrameError("BAD_TYPE", repr(self.type))
        if not _is_int(self.stream_id) or not 0 <= self.stream_id <= MAX_STREAM_ID:
            raise FrameError("BAD_STREAM_ID", repr(self.stream_id))
        if not _is_int(self.flags) or not 0 <= self.flags <= 0xFFFF:
            raise FrameError("BAD_FLAGS", repr(self.flags))
        for name, value, cap in (
            ("TOKEN", self.token, MAX_TOKEN_BYTES),
            ("POP", self.pop, MAX_POP_BYTES),
            ("BODY", self.body, MAX_BODY_BYTES),
        ):
            if not _is_bytes(value):
                raise FrameError(f"BAD_{name}", type(value).__name__)
            if len(value) > cap:
                raise FrameError(f"{name}_TOO_LARGE", str(len(value)))
        if self.payload_len > MAX_FRAME_BYTES:
            raise FrameError("FRAME_TOO_LARGE", str(self.payload_len))

    @property
    def payload_len(self) -> int:
        return FIXED_OVERHEAD + len(self.token) + len(self.pop) + len(self.body)


@dataclass(frozen=True, slots=True)
class FrameSpec:
    """Local wire constraints for one frame type. min_* == max_* means exact."""

    type_id: int
    name: str
    min_body: int = 0
    max_body: int = 0
    min_token: int = 0
    max_token: int = 0
    min_pop: int = 0
    max_pop: int = 0
    allowed_flags: int = Flags.NONE
    stream_id_rule: StreamIdRule = StreamIdRule.ZERO

    def __post_init__(self) -> None:
        if not _is_int(self.type_id) or not 1 <= self.type_id <= 0xFF:
            raise ValueError("type_id must be in 1..255")
        if (
            not isinstance(self.name, str)
            or not self.name
            or not self.name.isascii()
            or not all(c.isalnum() or c == "_" for c in self.name)
        ):
            raise ValueError("name must be non-empty ASCII alphanumeric/underscore")
        for lo, hi, cap in (
            (self.min_body, self.max_body, MAX_BODY_BYTES),
            (self.min_token, self.max_token, MAX_TOKEN_BYTES),
            (self.min_pop, self.max_pop, MAX_POP_BYTES),
        ):
            if not (_is_int(lo) and _is_int(hi) and 0 <= lo <= hi <= cap):
                raise ValueError(f"{self.name}: invalid length bounds {lo}..{hi}")
        if not _is_int(self.allowed_flags) or not 0 <= self.allowed_flags <= 0xFFFF:
            raise ValueError(f"{self.name}: allowed_flags must be in 0..0xFFFF")
        if self.allowed_flags & ~Flags.ALL:
            raise ValueError(f"{self.name}: allowed_flags has undefined bits")
        if not isinstance(self.stream_id_rule, StreamIdRule):
            raise ValueError(f"{self.name}: stream_id_rule must be StreamIdRule")
        if FIXED_OVERHEAD + self.max_token + self.max_pop + self.max_body > MAX_FRAME_BYTES:
            raise ValueError(f"{self.name}: exceeds MAX_FRAME_BYTES")

    def validate_header(
        self, *, flags: int, stream_id: int, token_len: int, payload_len: int
    ) -> None:
        """O(1) prologue validation, executed BEFORE the payload tail is read."""
        if not 0 <= stream_id <= MAX_STREAM_ID:
            raise FrameError("BAD_STREAM_ID", self.name)
        if self.stream_id_rule is StreamIdRule.ZERO and stream_id != 0:
            raise FrameError("BAD_STREAM_ID", f"{self.name} requires stream_id == 0")
        if self.stream_id_rule is StreamIdRule.NONZERO and stream_id == 0:
            raise FrameError("BAD_STREAM_ID", f"{self.name} requires stream_id > 0")
        if flags & ~self.allowed_flags:
            raise FrameError("BAD_FLAGS", f"{self.name}: 0x{flags:04x}")
        if not self.min_token <= token_len <= self.max_token:
            raise FrameError("BAD_TOKEN_LEN", f"{self.name}: {token_len}")
        base = FIXED_OVERHEAD + token_len
        if not (base + self.min_pop + self.min_body
                <= payload_len
                <= base + self.max_pop + self.max_body):
            raise FrameError("BAD_PAYLOAD_LEN", f"{self.name}: {payload_len}")

    def validate(self, frame: Frame) -> None:
        if frame.type != self.type_id:
            raise FrameError("BAD_TYPE", self.name)
        self.validate_header(
            flags=frame.flags,
            stream_id=frame.stream_id,
            token_len=len(frame.token),
            payload_len=frame.payload_len,
        )
        if not self.min_pop <= len(frame.pop) <= self.max_pop:
            raise FrameError("BAD_POP_LEN", f"{self.name}: {len(frame.pop)}")
        if not self.min_body <= len(frame.body) <= self.max_body:
            raise FrameError("BAD_BODY_LEN", f"{self.name}: {len(frame.body)}")


class FrameRegistry:
    """Immutable table of trusted local FrameSpec definitions."""

    __slots__ = ("_specs",)

    def __init__(self, specs: Iterable[FrameSpec]) -> None:
        table: dict[int, FrameSpec] = {}
        names: set[str] = set()
        for spec in specs:
            if not isinstance(spec, FrameSpec):
                raise TypeError("FrameSpec required")
            if spec.type_id in table:
                raise ValueError(f"duplicate frame type: 0x{spec.type_id:02x}")
            if spec.name in names:
                raise ValueError(f"duplicate frame name: {spec.name}")
            table[spec.type_id] = spec
            names.add(spec.name)
        if not table:
            raise ValueError("registry must define at least one frame type")
        self._specs: Mapping[int, FrameSpec] = MappingProxyType(table)

    def get(self, type_id: int) -> Optional[FrameSpec]:
        return self._specs.get(type_id)

    def require(self, type_id: int) -> FrameSpec:
        spec = self._specs.get(type_id)
        if spec is None:
            raise FrameError("UNKNOWN_TYPE", f"0x{type_id:02x}")
        return spec

    def extend(self, *specs: FrameSpec) -> "FrameRegistry":
        return FrameRegistry((*self._specs.values(), *specs))

    def replace(self, *specs: FrameSpec) -> "FrameRegistry":
        merged = dict(self._specs)
        for spec in specs:
            if not isinstance(spec, FrameSpec):
                raise TypeError("FrameSpec required")
            merged[spec.type_id] = spec
        return FrameRegistry(merged.values())


class FrameType:
    SESSION_INIT = 0x01
    OPEN_STREAM = 0x02
    STREAM_DATA = 0x03
    WINDOW_UPDATE = 0x04
    CANCEL = 0x05
    PING = 0x06
    PONG = 0x07
    CLOSE = 0x08
    ERROR = 0x09
    DATA          = 0x0A

    @staticmethod
    def name(type_id: int) -> str:
        spec = DEFAULT_REGISTRY.get(type_id)
        return spec.name if spec is not None else f"UNKNOWN(0x{type_id & 0xFF:02x})"

    @staticmethod
    def valid(type_id: int) -> bool:
        return DEFAULT_REGISTRY.get(type_id) is not None


# Every registered type is dispatched by the session layer. There are no
# decodable-but-unroutable frame types (no dead surface).
DEFAULT_REGISTRY = FrameRegistry((
    FrameSpec(FrameType.SESSION_INIT, "SESSION_INIT",
              min_body=1, max_body=HELLO_MAX_BODY),

    FrameSpec(FrameType.DATA, "DATA",
          max_body=DATA_MAX_BODY,
          max_token=DATA_MAX_TOKEN,
          max_pop=DATA_MAX_POP,
          allowed_flags=Flags.NONE,
          stream_id_rule=StreamIdRule.ZERO),


    FrameSpec(FrameType.OPEN_STREAM, "OPEN_STREAM",
              min_body=3, max_body=OPEN_MAX_BODY,
              max_token=OPEN_MAX_TOKEN, max_pop=OPEN_MAX_POP,
              stream_id_rule=StreamIdRule.NONZERO),
    FrameSpec(FrameType.STREAM_DATA, "STREAM_DATA",
              min_body=8, max_body=8 + MAX_CHUNK_BYTES,
              min_pop=STREAM_MAC_BYTES, max_pop=STREAM_MAC_BYTES,
              allowed_flags=Flags.FIN,
              stream_id_rule=StreamIdRule.NONZERO),
    FrameSpec(FrameType.WINDOW_UPDATE, "WINDOW_UPDATE",
              min_body=4, max_body=4,
              stream_id_rule=StreamIdRule.NONZERO),
    FrameSpec(FrameType.CANCEL, "CANCEL",
              max_body=MAX_REASON_BYTES,
              stream_id_rule=StreamIdRule.NONZERO),
    FrameSpec(FrameType.PING, "PING",
              min_body=PING_NONCE_BYTES, max_body=PING_NONCE_BYTES),
    FrameSpec(FrameType.PONG, "PONG",
              min_body=PING_NONCE_BYTES, max_body=PING_NONCE_BYTES),
    FrameSpec(FrameType.CLOSE, "CLOSE", max_body=MAX_REASON_BYTES),
    FrameSpec(FrameType.ERROR, "ERROR", max_body=256),

))


@dataclass(frozen=True, slots=True)
class StreamChunk:
    stream_id: int
    seq: int
    data: bytes
    mac: bytes
    fin: bool


# ───────────────────────── constructors & parsers ─────────────────────────

def make_session_init(body: bytes) -> Frame:
    if not _is_bytes(body) or not 1 <= len(body) <= HELLO_MAX_BODY:
        raise FrameError("BAD_HELLO_BODY")
    return Frame(type=FrameType.SESSION_INIT, body=body)


def make_close(reason: str = "") -> Frame:
    return Frame(type=FrameType.CLOSE, body=_safe_ascii(reason, MAX_REASON_BYTES))


def make_error(code: str, detail: str = "") -> Frame:
    """Binary error body: u16be(len(code)) || code || detail.

    code:   1..48 chars, ASCII alnum or underscore.
    detail: printable ASCII; truncated to fit FrameSpec's max_body.
    """
    if not isinstance(code, str):
        raise FrameError("BAD_CODE", type(code).__name__)
    safe_code = "".join(
        c for c in code if c.isascii() and (c.isalnum() or c == "_")
    )[:_MAX_ERR_CODE] or "INTERNAL"
    code_b = safe_code.encode("ascii")

    detail_safe = "".join(
        c if 0x20 <= ord(c) <= 0x7E else "_" for c in str(detail)[:256]
    ).encode("ascii")

    # ERROR FrameSpec: max_body=256, so code_b + detail + 2 must fit
    room = 256 - 2 - len(code_b)
    detail_b = detail_safe[:room]

    return Frame(
        type=FrameType.ERROR,
        body=_ERR_LEN.pack(len(code_b)) + code_b + detail_b,
    )

def parse_error_body(body: bytes) -> tuple[str, str]:
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise FrameError("BAD_ERR_BODY", type(body).__name__)
    raw = bytes(body)
    if len(raw) < 3:
        raise FrameError("BAD_ERR_BODY", "too short")
    (n,) = _ERR_LEN.unpack_from(raw, 0)
    if not 1 <= n <= _MAX_ERR_CODE or 2 + n > len(raw):
        raise FrameError("BAD_ERR_BODY", f"code_len={n}")
    code = raw[2:2 + n]
    detail = raw[2 + n:]
    if not all(0x20 <= b <= 0x7E for b in detail):
        raise FrameError("BAD_ERR_DETAIL")
    try:
        return code.decode("ascii"), detail.decode("ascii")
    except UnicodeDecodeError:
        raise FrameError("BAD_ERR_CODE") from None

    

def parse_reason(body: bytes, *, field: str = "reason") -> str:
    """Strictly decode a CLOSE/CANCEL reason. Rejects non-printable bytes."""
    if not _is_bytes(body) or len(body) > MAX_REASON_BYTES:
        raise FrameError("BAD_REASON", field)
    if not _is_printable_ascii(body):
        raise FrameError("BAD_REASON", field)
    return body.decode("ascii")


def _check_kind(kind: str) -> bytes:
    if (
        not isinstance(kind, str)
        or not 1 <= len(kind) <= 64
        or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in kind)
    ):
        raise FrameError("BAD_KIND", repr(kind))
    return kind.encode("ascii")


def make_open_stream(
    *, stream_id: int, kind: str, payload: bytes = b"",
    token: bytes = b"", pop: bytes = b"",
) -> Frame:
    """OPEN_STREAM body: u16be(len(kind)) || kind_ascii || initial_payload."""
    if not _is_int(stream_id) or not 0 < stream_id <= MAX_STREAM_ID:
        raise FrameError("BAD_STREAM_ID", repr(stream_id))
    kind_bytes = _check_kind(kind)
    if not _is_bytes(payload):
        raise FrameError("BAD_PAYLOAD", type(payload).__name__)
    frame = Frame(
        type=FrameType.OPEN_STREAM,
        stream_id=stream_id,
        token=token,
        pop=pop,
        body=_U16.pack(len(kind_bytes)) + kind_bytes + payload,
    )
    DEFAULT_REGISTRY.require(FrameType.OPEN_STREAM).validate(frame)
    return frame


def parse_open_stream_body(body: bytes) -> tuple[str, bytes]:
    """Parse a raw OPEN_STREAM body into (kind, initial_payload)."""
    if not _is_bytes(body) or len(body) < 3 or len(body) > OPEN_MAX_BODY:
        raise FrameError("TRUNCATED_OPEN_STREAM")
    kind_len = _U16.unpack_from(body, 0)[0]
    if not 1 <= kind_len <= 64 or 2 + kind_len > len(body):
        raise FrameError("BAD_KIND")
    raw_kind = body[2:2 + kind_len]
    if any(b <= 0x20 or b >= 0x7F for b in raw_kind):
        raise FrameError("BAD_KIND")
    return raw_kind.decode("ascii"), body[2 + kind_len:]


def parse_open_stream(
    frame: Frame, *, registry: FrameRegistry = DEFAULT_REGISTRY
) -> tuple[str, bytes]:
    if frame.type != FrameType.OPEN_STREAM:
        raise FrameError("BAD_TYPE", FrameType.name(frame.type))
    registry.require(FrameType.OPEN_STREAM).validate(frame)
    return parse_open_stream_body(frame.body)


def make_stream_data(
    *, stream_id: int, seq: int, data: bytes, mac: bytes, fin: bool = False
) -> Frame:
    """STREAM_DATA: body = u64be(seq) || data, pop = 32-byte MAC."""
    if not _is_int(stream_id) or not 0 < stream_id <= MAX_STREAM_ID:
        raise FrameError("BAD_STREAM_ID", repr(stream_id))
    if not _is_int(seq) or not 0 <= seq <= MAX_SEQ:
        raise FrameError("BAD_SEQ", repr(seq))
    if not _is_bytes(data) or len(data) > MAX_CHUNK_BYTES:
        raise FrameError("BAD_CHUNK")
    if not _is_bytes(mac) or len(mac) != STREAM_MAC_BYTES:
        raise FrameError("BAD_MAC")
    if type(fin) is not bool:
        raise FrameError("BAD_FIN")
    if not data and not fin:
        raise FrameError("EMPTY_CHUNK")
    return Frame(
        type=FrameType.STREAM_DATA,
        stream_id=stream_id,
        flags=Flags.FIN if fin else Flags.NONE,
        pop=mac,
        body=_U64.pack(seq) + data,
    )


def parse_stream_data(
    frame: Frame, *, registry: FrameRegistry = DEFAULT_REGISTRY
) -> StreamChunk:
    if frame.type != FrameType.STREAM_DATA:
        raise FrameError("BAD_TYPE", FrameType.name(frame.type))
    registry.require(FrameType.STREAM_DATA).validate(frame)
    seq = _U64.unpack_from(frame.body, 0)[0]
    if seq > MAX_SEQ:
        raise FrameError("BAD_SEQ", str(seq))
    data = frame.body[8:]
    fin = bool(frame.flags & Flags.FIN)
    if not data and not fin:
        raise FrameError("EMPTY_CHUNK")
    return StreamChunk(
        stream_id=frame.stream_id, seq=seq, data=data, mac=frame.pop, fin=fin
    )


def make_window_update(*, stream_id: int, credits: int) -> Frame:
    if not _is_int(stream_id) or not 0 < stream_id <= MAX_STREAM_ID:
        raise FrameError("BAD_STREAM_ID", repr(stream_id))
    if not _is_int(credits) or not 1 <= credits <= MAX_WINDOW_CREDIT:
        raise FrameError("BAD_CREDITS", repr(credits))
    return Frame(
        type=FrameType.WINDOW_UPDATE, stream_id=stream_id, body=_U32.pack(credits)
    )


def parse_window_update(
    frame: Frame, *, registry: FrameRegistry = DEFAULT_REGISTRY
) -> tuple[int, int]:
    if frame.type != FrameType.WINDOW_UPDATE:
        raise FrameError("BAD_TYPE", FrameType.name(frame.type))
    registry.require(FrameType.WINDOW_UPDATE).validate(frame)
    credits = _U32.unpack(frame.body)[0]
    if not 1 <= credits <= MAX_WINDOW_CREDIT:
        raise FrameError("BAD_CREDITS", str(credits))
    return frame.stream_id, credits


def make_cancel(*, stream_id: int, reason: str = "") -> Frame:
    if not _is_int(stream_id) or not 0 < stream_id <= MAX_STREAM_ID:
        raise FrameError("BAD_STREAM_ID", repr(stream_id))
    return Frame(
        type=FrameType.CANCEL,
        stream_id=stream_id,
        body=_safe_ascii(reason, MAX_REASON_BYTES),
    )


def _nonce_frame(type_id: int, nonce: bytes) -> Frame:
    if not _is_bytes(nonce) or len(nonce) != PING_NONCE_BYTES:
        raise FrameError("BAD_NONCE", str(len(nonce) if _is_bytes(nonce) else -1))
    return Frame(type=type_id, body=nonce)


def make_ping(*, nonce: bytes) -> Frame:
    return _nonce_frame(FrameType.PING, nonce)


def make_pong(*, nonce: bytes) -> Frame:
    return _nonce_frame(FrameType.PONG, nonce)


def fits(token: bytes, pop: bytes, body_len: int, max_frame: int) -> bool:
    return FIXED_OVERHEAD + len(token) + len(pop) + body_len <= max_frame


# ───────────────────────── codec ─────────────────────────

def _decode_tail(
    prologue: bytes, tail: bytes, payload_len: int, spec: FrameSpec
) -> Frame:
    type_id, flags, stream_id, token_len = _PROLOGUE.unpack(prologue)
    if len(tail) != payload_len - PROLOGUE_LEN:
        raise FrameError("LENGTH_MISMATCH")
    if len(tail) < token_len + _LEN_LEN:
        raise FrameError("TRUNCATED_TOKEN")
    pop_len = _U32.unpack_from(tail, token_len)[0]
    if not spec.min_pop <= pop_len <= spec.max_pop:
        raise FrameError("BAD_POP_LEN", spec.name)
    pop_start = token_len + _LEN_LEN
    pop_end = pop_start + pop_len
    if pop_end > len(tail):
        raise FrameError("TRUNCATED_POP", spec.name)
    frame = Frame(
        type=type_id,
        stream_id=stream_id,
        flags=flags,
        token=tail[:token_len],
        pop=tail[pop_start:pop_end],
        body=tail[pop_end:],
    )
    spec.validate(frame)
    return frame


def encode_frame(
    frame: Frame, *, registry: FrameRegistry = DEFAULT_REGISTRY
) -> bytes:
    if not isinstance(frame, Frame):
        raise FrameError("BAD_FRAME")
    registry.require(frame.type).validate(frame)
    return b"".join((
        _U32.pack(frame.payload_len),
        _PROLOGUE.pack(frame.type, frame.flags, frame.stream_id, len(frame.token)),
        frame.token,
        _U32.pack(len(frame.pop)),
        frame.pop,
        frame.body,
    ))


def decode_frame(
    data: object, *, registry: FrameRegistry = DEFAULT_REGISTRY
) -> Frame:
    """Decode exactly one complete wire frame. Raises only FrameError."""
    if type(data) is bytes:
        raw = data
    elif isinstance(data, (bytearray, memoryview)):
        try:
            view = memoryview(data)
            if not view.c_contiguous:
                raise FrameError("BAD_INPUT", "non-contiguous buffer")
            view = view.cast("B")
        except FrameError:
            raise
        except Exception as exc:
            raise FrameError("BAD_INPUT", type(exc).__name__) from None
        if not HEADER_LEN + FIXED_OVERHEAD <= view.nbytes <= HEADER_LEN + MAX_FRAME_BYTES:
            raise FrameError("BAD_INPUT_LEN", str(view.nbytes))
        raw = view.tobytes()
    else:
        raise FrameError("BAD_INPUT", type(data).__name__)

    if len(raw) < HEADER_LEN + FIXED_OVERHEAD:
        raise FrameError("TOO_SHORT")
    payload_len = _U32.unpack_from(raw, 0)[0]
    if not FIXED_OVERHEAD <= payload_len <= MAX_FRAME_BYTES:
        raise FrameError("BAD_PAYLOAD_LEN", str(payload_len))
    if len(raw) != HEADER_LEN + payload_len:
        raise FrameError("LENGTH_MISMATCH")

    prologue = raw[HEADER_LEN:HEADER_LEN + PROLOGUE_LEN]
    type_id, flags, stream_id, token_len = _PROLOGUE.unpack(prologue)
    spec = registry.require(type_id)
    spec.validate_header(
        flags=flags, stream_id=stream_id,
        token_len=token_len, payload_len=payload_len,
    )
    return _decode_tail(prologue, raw[HEADER_LEN + PROLOGUE_LEN:], payload_len, spec)

def make_data(
    *,
    token: bytes = b"",
    pop: bytes = b"",
    body: bytes = b"",
    stream_id: int = 0,
) -> Frame:
    """Session-scoped authenticated message.

    `token` is the credential, `pop` is proof-of-possession binding that
    credential to this connection, `body` is opaque to the frame layer.
    Whether a DATA frame *must* carry a token is a session-layer policy —
    the frame spec does not enforce it, because the session layer is what
    defines "authenticated DATA".
    """
    if not _is_bytes(token):
        raise FrameError("BAD_TOKEN", type(token).__name__)
    if not _is_bytes(pop):
        raise FrameError("BAD_POP", type(pop).__name__)
    if not _is_bytes(body):
        raise FrameError("BAD_BODY", type(body).__name__)
    if not _is_int(stream_id):
        raise FrameError("BAD_STREAM_ID", repr(stream_id))
    frame = Frame(
        type=FrameType.DATA,
        stream_id=stream_id,
        token=token,
        pop=pop,
        body=body,
    )
    DEFAULT_REGISTRY.require(FrameType.DATA).validate(frame)
    return frame
# ───────────────────────── async I/O ─────────────────────────

class ByteReader(Protocol):
    async def readexactly(self, n: int) -> bytes: ...


class ByteWriter(Protocol):
    def write(self, data: bytes) -> None: ...
    async def drain(self) -> None: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...


@dataclass(frozen=True, slots=True)
class FrameReceived:
    frame: Frame


@dataclass(frozen=True, slots=True)
class StreamClosed:
    reason: str


@dataclass(frozen=True, slots=True)
class FrameWritten:
    bytes_sent: int


@dataclass(frozen=True, slots=True)
class StreamCloseSucceeded:
    pass


@dataclass(frozen=True, slots=True)
class StreamCloseFailed:
    reason: str


RecvOutcome = Union[FrameReceived, StreamClosed]
WriteOutcome = Union[FrameWritten, StreamClosed]
CloseOutcome = Union[StreamCloseSucceeded, StreamCloseFailed]


def _to_timeout(value: object, name: str) -> Optional[float]:
    if value is None:
        return None
    if not isinstance(value, (int, float)):
        raise FrameError("BAD_TIMEOUT", name)
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise FrameError("BAD_TIMEOUT", name)
    return seconds


def _to_limit(value: object) -> int:
    if value is None:
        return MAX_FRAME_BYTES
    if not _is_int(value) or value < FIXED_OVERHEAD:
        raise FrameError("BAD_LIMIT", repr(value))
    return min(value, MAX_FRAME_BYTES)


def _remaining(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    rem = deadline - asyncio.get_running_loop().time()
    if rem <= 0:
        raise asyncio.TimeoutError
    return rem


class FrameReader:
    """One serialized reader. Any malformed frame closes it permanently."""

    __slots__ = ("_reader", "_registry", "_lock", "_closed")

    def __init__(
        self, reader: ByteReader, *, registry: FrameRegistry = DEFAULT_REGISTRY
    ) -> None:
        self._reader = reader
        self._registry = registry
        self._lock = asyncio.Lock()
        self._closed: Optional[str] = None

    @property
    def closed(self) -> bool:
        return self._closed is not None

    @property
    def close_reason(self) -> Optional[str]:
        return self._closed

    def close(self, reason: str = "local_close") -> None:
        if self._closed is None:
            self._closed = reason

    def _end(self, reason: str) -> StreamClosed:
        self.close(reason)
        return StreamClosed(self._closed or reason)

    async def _exact(
        self, n: int, deadline: Optional[float], *, frame_boundary: bool = False
    ) -> Union[bytes, StreamClosed]:
        try:
            rem = _remaining(deadline)
            if rem is None:
                data = await self._reader.readexactly(n)
            else:
                data = await asyncio.wait_for(self._reader.readexactly(n), rem)
        except asyncio.TimeoutError:                 # must precede OSError on 3.11+
            if frame_boundary:
                return self._end("idle_timeout")
            self.close("frame_timeout")
            raise FrameError("FRAME_TIMEOUT", str(n)) from None
        except asyncio.IncompleteReadError as exc:
            if frame_boundary and not exc.partial:
                return self._end("eof")              # clean EOF at a frame boundary
            self.close("protocol")
            raise FrameError("TRUNCATED", f"{len(exc.partial)}/{n}") from None
        except asyncio.CancelledError:
            self.close("cancelled")                  # bytes may be partly consumed
            raise
        except (ConnectionError, OSError):
            return self._end("connection")
        except Exception as exc:
            self.close("read_error")
            raise FrameError("READ_ERROR", type(exc).__name__) from None

        if type(data) is not bytes or len(data) != n:
            self.close("protocol")
            raise FrameError("BAD_READ_RESULT")
        return data

    async def read_frame(
        self,
        *,
        idle_timeout: Optional[float] = None,
        frame_timeout: Optional[float] = None,
        max_payload: Union[int, Callable[[], int], None] = None,
    ) -> RecvOutcome:
        """idle_timeout bounds the wait for the first byte; frame_timeout bounds
        the rest of the frame once the length prefix has been consumed."""
        idle_timeout = _to_timeout(idle_timeout, "idle_timeout")
        frame_timeout = _to_timeout(frame_timeout, "frame_timeout")
        dynamic = callable(max_payload)
        static_limit = None if dynamic else _to_limit(max_payload)

        # Cancellation while waiting for the lock consumes nothing.
        async with self._lock:
            if self._closed is not None:
                return StreamClosed(self._closed)
            loop = asyncio.get_running_loop()

            # 1. Length prefix, under the idle deadline.
            idle_deadline = None if idle_timeout is None else loop.time() + idle_timeout
            prefix = await self._exact(HEADER_LEN, idle_deadline, frame_boundary=True)
            if isinstance(prefix, StreamClosed):
                return prefix
            payload_len = _U32.unpack(prefix)[0]

            # Everything past this point is fail-closed.
            deadline = None if frame_timeout is None else loop.time() + frame_timeout

            # 2. Global limit. A callable is evaluated after the prefix, so a
            #    phase change while suspended takes effect immediately.
            try:
                limit = _to_limit(max_payload()) if dynamic else static_limit
            except FrameError:
                self.close("protocol")
                raise
            except Exception as exc:
                self.close("protocol")
                raise FrameError("BAD_LIMIT", type(exc).__name__) from None
            if not FIXED_OVERHEAD <= payload_len <= limit:
                self.close("protocol")
                raise FrameError("BAD_PAYLOAD_LEN", str(payload_len))

            # 3. Prologue and per-type checks before the bulk read.
            prologue = await self._exact(PROLOGUE_LEN, deadline)
            if isinstance(prologue, StreamClosed):
                return prologue
            type_id, flags, stream_id, token_len = _PROLOGUE.unpack(prologue)
            try:
                spec = self._registry.require(type_id)
                spec.validate_header(
                    flags=flags, stream_id=stream_id,
                    token_len=token_len, payload_len=payload_len,
                )
            except FrameError:
                self.close("protocol")
                raise

            # 4. Tail, now bounded by this type's spec.
            tail = await self._exact(payload_len - PROLOGUE_LEN, deadline)
            if isinstance(tail, StreamClosed):
                return tail
            try:
                return FrameReceived(_decode_tail(prologue, tail, payload_len, spec))
            except FrameError:
                self.close("protocol")
                raise


class FrameWriter:
    """One serialized writer with no frame queue.

    Lock order: _lock, then _close_task. close() never takes _lock, so a stalled
    drain() can never block shutdown.
    """

    __slots__ = (
        "_writer", "_registry", "_lock", "_write_timeout",
        "_close_timeout", "_closed", "_close_task",
    )

    def __init__(
        self,
        writer: ByteWriter,
        *,
        write_timeout: Optional[float] = WRITE_TIMEOUT,
        close_timeout: float = CLOSE_TIMEOUT,
        registry: FrameRegistry = DEFAULT_REGISTRY,
    ) -> None:
        self._writer = writer
        self._registry = registry
        self._lock = asyncio.Lock()
        self._write_timeout = _to_timeout(write_timeout, "write_timeout")
        self._close_timeout = _to_timeout(close_timeout, "close_timeout")
        if self._close_timeout is None:
            raise FrameError("BAD_TIMEOUT", "close_timeout must be finite")
        self._closed: Optional[str] = None
        self._close_task: Optional[asyncio.Task[CloseOutcome]] = None

    @property
    def closed(self) -> bool:
        return self._closed is not None

    @property
    def busy(self) -> bool:
        """True while a write/drain holds the lock. Used to skip best-effort
        sends during shutdown rather than wait out a stalled peer."""
        return self._lock.locked()

    def _limit(self, timeout=None):
         return self._write_timeout if timeout is None else _to_timeout(timeout, "timeout")

    async def _shutdown(self) -> CloseOutcome:
        try:
            await asyncio.wait_for(self._writer.wait_closed(), self._close_timeout)
        except asyncio.TimeoutError:                 # must precede OSError on 3.11+
            self._abort()
            return StreamCloseFailed("close_timeout")
        except (ConnectionError, OSError):
            return StreamCloseSucceeded()            # peer already gone: closed
        except asyncio.CancelledError:
            # Reached only if this shared task is cancelled directly (callers
            # await it under shield). Treat as a failed close, not a leak.
            self._abort()
            return StreamCloseFailed("cancelled")
        except Exception as exc:
            self._abort()
            return StreamCloseFailed(type(exc).__name__)
        return StreamCloseSucceeded()

    def _abort(self) -> None:
        abort = getattr(getattr(self._writer, "transport", None), "abort", None)
        if callable(abort):
            try:
                abort()
            except Exception:
                pass

    def _begin_close(self, reason: str) -> asyncio.Task[CloseOutcome]:
        if self._closed is None:
            self._closed = reason
        if self._close_task is None:
            try:
                self._writer.close()
            except Exception:
                pass
            self._close_task = asyncio.get_running_loop().create_task(self._shutdown())
        return self._close_task

    def abort(self, reason: str = "abort") -> None:
        """Synchronous, idempotent close initiation. Safe from any context,
        including an except-CancelledError handler."""
        try:
            self._begin_close(reason)
        except RuntimeError:                         # no running loop
            if self._closed is None:
                self._closed = reason
            try:
                self._writer.close()
            except Exception:
                pass

    async def close(self, reason: str = "local_close") -> CloseOutcome:
        """Idempotent. A cancelled caller does not cancel the shared shutdown."""
        return await asyncio.shield(self._begin_close(reason))


    async def write_frame(
        self, frame: Frame, *, timeout: Optional[float] = None
    ) -> WriteOutcome:
        """timeout=None uses the configured write_timeout."""
        limit = self._limit(timeout)
        async with self._lock:
            if self._closed is not None:
                return StreamClosed(self._closed)

            data = encode_frame(frame, registry=self._registry)

            try:
                self._writer.write(data)
            except (ConnectionError, OSError) as exc:
                reason = self._closed or type(exc).__name__
                self._begin_close(reason)
                return StreamClosed(reason)
            except Exception as exc:
                reason = self._closed or type(exc).__name__
                self._begin_close(reason)
                return StreamClosed(reason)

            # The complete frame is queued; cancelling drain() leaves the
            # byte stream frame-aligned, so no resync is needed.
            try:
                if limit is None:
                    await self._writer.drain()
                else:
                    await asyncio.wait_for(self._writer.drain(), limit)
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                self._begin_close("write_timeout")
                return StreamClosed("write_timeout")
            except (ConnectionError, OSError) as exc:
                reason = self._closed or type(exc).__name__
                self._begin_close(reason)
                return StreamClosed(reason)
            except Exception as exc:
                reason = self._closed or type(exc).__name__
                self._begin_close(reason)
                return StreamClosed(reason)

            if self._closed is not None:
                return StreamClosed(self._closed)
            return FrameWritten(len(data))


class FrameStream:
    """Bidirectional framed connection. When either direction ends, both close."""

    __slots__ = ("reader", "writer")

    def __init__(
        self,
        reader: ByteReader,
        writer: ByteWriter,
        *,
        registry: FrameRegistry = DEFAULT_REGISTRY,
        write_timeout: Optional[float] = WRITE_TIMEOUT,
        close_timeout: float = CLOSE_TIMEOUT,
    ) -> None:
        self.reader = FrameReader(reader, registry=registry)
        self.writer = FrameWriter(
            writer,
            registry=registry,
            write_timeout=write_timeout,
            close_timeout=close_timeout,
        )

    @classmethod
    def from_tls(
        cls,
        conn: object,
        *,
        registry: FrameRegistry = DEFAULT_REGISTRY,
        write_timeout: Optional[float] = WRITE_TIMEOUT,
        close_timeout: float = CLOSE_TIMEOUT,
    ) -> "FrameStream":
        reader = getattr(conn, "reader", None)
        writer = getattr(conn, "writer", None)
        if reader is None or writer is None:
            raise FrameError("BAD_TLS_CONN", type(conn).__name__)
        return cls(
            reader, writer,
            registry=registry,
            write_timeout=write_timeout,
            close_timeout=close_timeout,
        )

    @property
    def closed(self) -> bool:
        return self.reader.closed or self.writer.closed

    async def recv(
        self,
        *,
        idle_timeout: Optional[float] = None,
        frame_timeout: Optional[float] = None,
        max_payload: Union[int, Callable[[], int], None] = None,
    ) -> RecvOutcome:
        try:
            out = await self.reader.read_frame(
                idle_timeout=idle_timeout,
                frame_timeout=frame_timeout,
                max_payload=max_payload,
            )
        except asyncio.CancelledError:
            # The reader is permanently closed; do not leave a half-open writer.
            self.writer.abort("cancelled")
            raise
        except FrameError:
            self.writer.abort("protocol")
            raise
        if isinstance(out, StreamClosed):
            await self.writer.close(out.reason)
        return out

    async def send(
        self, frame: Frame, *, timeout: Optional[float] = None
    ) -> WriteOutcome:
        out = await self.writer.write_frame(frame, timeout=timeout)
        if isinstance(out, StreamClosed):
            self.reader.close(out.reason)
            await self.writer.close(out.reason)
        return out

    async def close(self, reason: str = "local_close") -> CloseOutcome:
        self.reader.close(reason)
        return await self.writer.close(reason)

    async def __aenter__(self) -> "FrameStream":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        outcome = await self.close()
        if isinstance(outcome, StreamCloseFailed) and exc_type is None:
            raise StreamCloseError(outcome.reason)

