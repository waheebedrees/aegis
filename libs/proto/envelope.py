"""Envelope framing for the message layer (spec §3.1).

Layout:
    +-------+-------+-------+-------+
    | ver=1 | type  | flags | hlen  |   6-byte prefix
    +-------+-------+-------+-------+
    | headers (hlen bytes, TLV)     |
    +-------------------------------+
    | payload                       |
    +-------------------------------+

One envelope per transport chunk. DATA may fragment; END/ERROR terminate.
COMPRESSED is declared but not implemented in M1 — decode fails closed
so compressed bytes never reach the application codec.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from types import MappingProxyType

from libs.proto.status import (
    ProtocolError,
    Status,
    malformed,
    status_from_wire,
    error,
)
from libs.proto.tlv import TLVEntry, MsgType
from libs.proto.headers import HeaderRegistry, HeaderSpec


__all__ = [
    "MsgType",
    "MsgFlag",
    "HeaderTag",
    "MESSAGE_REGISTRY",
    "Envelope",
    "encode_envelope",
    "decode_envelope",
    "EndFrame",
    "make_end_headers",
    "PREFIX_LEN",
    "MAX_ENVELOPE_BYTES",
    "MAX_HDR_BYTES",
]

_PREFIX = struct.Struct(">BBHH")
_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")


PREFIX_LEN = _PREFIX.size
ENVELOPE_VERSION = 1
MAX_ENVELOPE_BYTES = 60 * 1024
MAX_HDR_BYTES = 4096
MAX_ERROR_MSG_LEN = 256


class MsgFlag:
    NONE = 0x0000
    FRAG_MORE = 0x0001
    COMPRESSED = 0x0002
    CRITICAL = 0x0004
    ALL = FRAG_MORE | COMPRESSED | CRITICAL


class HeaderTag(IntEnum):
    STATUS = 0x0001  # u16, required on END/ERROR
    MESSAGE = 0x0002  # ASCII <= 256
    SCHEMA_ID = 0x0003  # ASCII <= 128
    CONTENT_CODING = 0x0004  # ASCII <= 32
    SEQ = 0x0005  # u64
    RETRY_AFTER_MS = 0x0006  # u32
    DETAIL = 0x0007  # opaque
    E2E_SEALED = 0x0008  # reserved


MESSAGE_REGISTRY = HeaderRegistry(
    (
        HeaderSpec(
            HeaderTag.STATUS,
            2,
            2,
            True,
            frozenset((int(MsgType.END), int(MsgType.ERROR))),
        ),
        HeaderSpec(
            HeaderTag.MESSAGE,
            1,
            256,
            contexts=frozenset((int(MsgType.END), int(MsgType.ERROR))),
        ),
        HeaderSpec(
            HeaderTag.SCHEMA_ID,
            1,
            128,
            contexts=frozenset((int(MsgType.DATA),)),
        ),
        HeaderSpec(
            HeaderTag.RETRY_AFTER_MS,
            4,
            4,
            contexts=frozenset((int(MsgType.ERROR),)),
        ),
        HeaderSpec(HeaderTag.DETAIL, 1, 1024, contexts=frozenset((int(MsgType.ERROR),))),
    )
)


@dataclass(frozen=True, slots=True)
class Envelope:
    type: MsgType
    headers: tuple[TLVEntry, ...] = ()
    payload: bytes = b""
    flags: int = MsgFlag.NONE

    @property
    def is_frag_more(self) -> bool:
        return bool(self.flags & MsgFlag.FRAG_MORE)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & MsgFlag.COMPRESSED)

    @property
    def is_critical(self) -> bool:
        return bool(self.flags & MsgFlag.CRITICAL)

    @property
    def terminal(self) -> bool:
        return self.type in (MsgType.END, MsgType.ERROR)

    def header(self, tag: int) -> bytes | None:
        for h in self.headers:
            if h.tag == tag:
                return h.value
        return None

    def status(self) -> tuple[Status, int]:
        raw = self.header(HeaderTag.STATUS)
        if raw is None or len(raw) != 2:
            raise error(Status.MALFORMED, "terminal without STATUS")
        return status_from_wire(struct.unpack(">H", raw)[0])

    def _validate(self, *, inbound: bool, known_app: frozenset[int] = frozenset()) -> None:
        bad = Status.MALFORMED if inbound else Status.INVALID_ARGUMENT
        if self.type in (MsgType.CONTROL, MsgType.CREDIT):
            raise error(
                Status.UNIMPLEMENTED if inbound else bad,
                f"{self.type.name} reserved in v1",
            )


def encode_envelope(
    env: Envelope,
    registry: HeaderRegistry = MESSAGE_REGISTRY,
) -> bytes:
    if env.flags & ~MsgFlag.ALL:
        raise ProtocolError(
            Status.INVALID_ARGUMENT,
            f"unknown envelope flags 0x{env.flags:04x}",
        )
    hdr = (
        registry.encode(
            env.headers,
            max_bytes=MAX_HDR_BYTES,
            max_fields=32,
            context=int(env.type),
        )
        if env.headers
        else b""
    )
    body = _PREFIX.pack(ENVELOPE_VERSION, int(env.type), env.flags, len(hdr)) + hdr + env.payload
    if len(body) > MAX_ENVELOPE_BYTES:
        raise ProtocolError(Status.OUT_OF_RANGE, f"envelope {len(body)}B")
    return body


def decode_envelope(
    raw: bytes,
    registry: HeaderRegistry = MESSAGE_REGISTRY,
) -> Envelope:
    if type(raw) is not bytes or len(raw) < PREFIX_LEN:
        raise malformed("truncated envelope")
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ProtocolError(Status.OUT_OF_RANGE, "envelope too large")
    version, kind, flags, hlen = _PREFIX.unpack_from(raw, 0)
    if version != ENVELOPE_VERSION:
        raise malformed(f"envelope version {version}")
    try:
        msg_type = MsgType(kind)
    except ValueError:
        raise malformed(f"unknown MsgType {kind}") from None
    if flags & ~MsgFlag.ALL:
        raise malformed(f"unknown envelope flags 0x{flags:04x}")
    if PREFIX_LEN + hlen > len(raw):
        raise malformed("truncated envelope headers")
    if hlen > MAX_HDR_BYTES:
        raise ProtocolError(Status.OUT_OF_RANGE, "headers too large")
    hdr_bytes = raw[PREFIX_LEN : PREFIX_LEN + hlen]
    payload = raw[PREFIX_LEN + hlen :]
    headers = (
        registry.decode(
            hdr_bytes,
            max_bytes=MAX_HDR_BYTES,
            max_fields=32,
            context=int(msg_type),
        )
        if hlen
        else ()
    )
    if flags & MsgFlag.CRITICAL:
        for entry in headers:
            if int(entry.tag) not in HeaderTag._value2member_map_:
                raise ProtocolError(
                    Status.UNIMPLEMENTED,
                    f"unknown header 0x{int(entry.tag):04x} in CRITICAL envelope",
                )

    return Envelope(type=msg_type, headers=headers, payload=payload, flags=flags)


def make_end_headers(
    status: Status,
    message: str = "",
    *,
    detail: bytes = b"",
    retry_after_ms: int = 0,
    trailers: Mapping[int, bytes] | None = None,
) -> tuple[TLVEntry, ...]:
    fields: list[TLVEntry] = []
    if trailers:
        for tag, value in trailers.items():
            fields.append(TLVEntry(int(tag), value))
    fields.append(TLVEntry(HeaderTag.STATUS, _U16.pack(int(status)), True))
    if message:
        safe = "".join(c if 0x20 <= ord(c) <= 0x7E else "_" for c in message[:MAX_ERROR_MSG_LEN])
        fields.append(TLVEntry(HeaderTag.MESSAGE, safe.encode("ascii")))
    if retry_after_ms:
        if not 1 <= retry_after_ms <= 0xFFFFFFFF:
            raise ProtocolError(Status.INVALID_ARGUMENT, "retry_after_ms")
        fields.append(TLVEntry(HeaderTag.RETRY_AFTER_MS, _U32.pack(retry_after_ms)))
    if detail:
        fields.append(TLVEntry(HeaderTag.DETAIL, detail))
    return tuple(fields)


@dataclass(frozen=True, slots=True)
class EndFrame:
    status: Status
    message: str = ""
    retry_after_ms: int = 0
    detail: bytes = b""
    trailers: Mapping[int, bytes] = field(default_factory=dict)

    @classmethod
    def parse(cls, is_error: bool, headers: tuple[TLVEntry, ...]) -> EndFrame:
        by_tag = {int(e.tag): e.value for e in headers}
        raw = by_tag.get(HeaderTag.STATUS)
        if raw is None:
            if is_error:
                raise malformed("ERROR requires STATUS header")
            status = Status.OK
        else:
            if len(raw) != 2:
                raise malformed("STATUS must be 2 bytes")
            value = _U16.unpack(raw)[0]
            if not Status.valid(value):
                raise malformed(f"invalid status {value}")
            status = Status(value)
            if is_error and status is Status.OK:
                raise malformed("ERROR cannot carry Status.OK")
        raw_msg = by_tag.get(HeaderTag.MESSAGE, b"")
        if len(raw_msg) > MAX_ERROR_MSG_LEN:
            raise malformed("MESSAGE too long")
        try:
            message = raw_msg.decode("ascii") if raw_msg else ""
        except UnicodeDecodeError:
            raise malformed("MESSAGE not ASCII") from None
        retry = (
            _U32.unpack(by_tag[HeaderTag.RETRY_AFTER_MS])[0]
            if HeaderTag.RETRY_AFTER_MS in by_tag
            else 0
        )
        detail = by_tag.get(HeaderTag.DETAIL, b"")
        trailers = {
            int(k): v
            for k, v in by_tag.items()
            if int(k)
            not in (
                HeaderTag.STATUS,
                HeaderTag.MESSAGE,
                HeaderTag.RETRY_AFTER_MS,
                HeaderTag.DETAIL,
            )
        }
        return cls(
            status=status,
            message=message,
            retry_after_ms=retry,
            detail=detail,
            trailers=MappingProxyType(trailers),
        )
