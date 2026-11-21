from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from libs.proto.status import ProtocolError, Status, malformed
from libs.proto.tlv import TLVEntry
from libs.proto.headers import HeaderSpec, HeaderRegistry

__all__ = [
    "Mode",
    "HelloTag",
    "ChannelHello",
    "HELLO_REGISTRY",
    "MAX_HELLO_BYTES",
]

_U32 = struct.Struct(">I")


MAX_HELLO_BYTES = 3584


class Mode(IntEnum):
    UNARY = 1
    CLIENT_STREAM = 2
    SERVER_STREAM = 3
    BIDI = 4
    DATAGRAM = 5


class HelloTag(IntEnum):
    MODE = 0x0001
    CONTENT_TYPE = 0x0002
    METHOD = 0x0003
    DEADLINE_MS = 0x0004
    CORRELATION_ID = 0x0005
    TRACE_PARENT = 0x0006
    IDEMPOTENCY_KEY = 0x0007
    ACCEPT_TYPES = 0x0008
    SCHEMA_ID = 0x0009
    PRIORITY = 0x000A
    INITIAL_CREDIT = 0x000B


HELLO_REGISTRY = HeaderRegistry(
    (
        HeaderSpec(HelloTag.MODE, 1, 1, True),
        HeaderSpec(HelloTag.CONTENT_TYPE, 1, 64, True),
        HeaderSpec(HelloTag.METHOD, 1, 128, True),
        HeaderSpec(HelloTag.DEADLINE_MS, 4, 4),
        HeaderSpec(HelloTag.CORRELATION_ID, 16, 16),
        HeaderSpec(HelloTag.TRACE_PARENT, 1, 64),
        HeaderSpec(HelloTag.IDEMPOTENCY_KEY, 1, 32),
        HeaderSpec(HelloTag.ACCEPT_TYPES, 1, 256),
        HeaderSpec(HelloTag.SCHEMA_ID, 1, 128),
        HeaderSpec(HelloTag.PRIORITY, 1, 1),
        HeaderSpec(HelloTag.INITIAL_CREDIT, 1, 1),
    )
)


def _ascii(text: object, name: str, lo: int, hi: int) -> bytes:
    if not isinstance(text, str):
        raise malformed(f"{name} must be str")
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError:
        raise malformed(f"{name} must be ascii") from None
    if not lo <= len(raw) <= hi or any(b < 0x21 or b > 0x7E for b in raw):
        raise malformed(f"{name} invalid")
    return raw


@dataclass(frozen=True, slots=True)
class ChannelHello:
    mode: Mode
    method: str = ""
    content_type: str = "application/cbor"
    deadline_ms: int = 0
    correlation_id: bytes = b""
    traceparent: str = ""
    idempotency_key: bytes = b""
    accept_types: tuple[str, ...] = ()
    schema_id: str = ""
    priority: int = 0
    initial_credit: int = 0
    extensions: tuple[TLVEntry, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.mode, Mode):
            raise malformed("mode")
        if self.mode is not Mode.DATAGRAM and not self.method:
            raise malformed("method required for non-DATAGRAM")
        if self.method:
            _ascii(self.method, "method", 1, 128)
        _ascii(self.content_type, "content_type", 1, 64)
        if type(self.deadline_ms) is not int or not 0 <= self.deadline_ms <= 0xFFFFFFFF:
            raise malformed("deadline_ms")
        if self.correlation_id and (
            type(self.correlation_id) is not bytes or len(self.correlation_id) != 16
        ):
            raise malformed("correlation_id")
        if self.traceparent:
            _ascii(self.traceparent, "traceparent", 1, 64)
        if type(self.idempotency_key) is not bytes or len(self.idempotency_key) > 32:
            raise malformed("idempotency_key")
        if not isinstance(self.accept_types, tuple):
            raise malformed("accept_types")
        for accept in self.accept_types:
            _ascii(accept, "accept_type", 1, 64)
        if self.schema_id:
            _ascii(self.schema_id, "schema_id", 1, 128)
        if type(self.priority) is not int or not 0 <= self.priority <= 7:
            raise malformed("priority")
        for ext in self.extensions:
            if not isinstance(ext, TLVEntry) or ext.tag < 0x1000:
                raise malformed("extension tag")
        if type(self.initial_credit) is not int or not 0 <= self.initial_credit <= 0x7FFFFFFF:
            raise ProtocolError(Status.MALFORMED, "initial_credit out of range")
        if self.initial_credit and self.mode is not Mode.BIDI:
            raise ProtocolError(Status.MALFORMED, "INITIAL_CREDIT only valid for BIDI")

    def encode(self, registry: HeaderRegistry = HELLO_REGISTRY) -> bytes:
        fields: list[TLVEntry] = [
            TLVEntry(HelloTag.MODE, bytes((self.mode,)), True),
            TLVEntry(
                HelloTag.CONTENT_TYPE,
                _ascii(self.content_type, "content_type", 1, 64),
                True,
            ),
        ]
        if self.method:
            fields.append(TLVEntry(HelloTag.METHOD, _ascii(self.method, "method", 1, 128), True))
        if self.deadline_ms:
            fields.append(TLVEntry(HelloTag.DEADLINE_MS, _U32.pack(self.deadline_ms)))
        if self.correlation_id:
            fields.append(TLVEntry(HelloTag.CORRELATION_ID, self.correlation_id))
        if self.traceparent:
            fields.append(
                TLVEntry(
                    HelloTag.TRACE_PARENT,
                    _ascii(self.traceparent, "traceparent", 1, 64),
                )
            )
        if self.idempotency_key:
            fields.append(TLVEntry(HelloTag.IDEMPOTENCY_KEY, self.idempotency_key))
        if self.accept_types:
            joined = ",".join(self.accept_types)
            fields.append(
                TLVEntry(
                    HelloTag.ACCEPT_TYPES,
                    _ascii(joined, "accept_types", 1, 256),
                )
            )
        if self.schema_id:
            fields.append(
                TLVEntry(
                    HelloTag.SCHEMA_ID,
                    _ascii(self.schema_id, "schema_id", 1, 128),
                )
            )
        if self.priority:
            fields.append(TLVEntry(HelloTag.PRIORITY, bytes((self.priority,))))

        if self.initial_credit:
            fields.append(TLVEntry(HelloTag.INITIAL_CREDIT, bytes((self.initial_credit,))))

        fields.extend(self.extensions)
        return registry.encode(fields, max_bytes=MAX_HELLO_BYTES, max_fields=32)

    @classmethod
    def decode(
        cls,
        raw: bytes,
        registry: HeaderRegistry = HELLO_REGISTRY,
    ) -> "ChannelHello":
        if type(raw) is not bytes or not raw:
            raise malformed("empty hello")
        fields = registry.decode(raw, max_bytes=MAX_HELLO_BYTES, max_fields=32)
        by_tag: dict[int, bytes] = {}
        ext: list[TLVEntry] = []
        for entry in fields:
            if int(entry.tag) in HelloTag._value2member_map_:
                by_tag[int(entry.tag)] = entry.value
            else:
                ext.append(entry)
        for required in (HelloTag.MODE, HelloTag.CONTENT_TYPE):
            if int(required) not in by_tag:
                raise malformed(f"missing hello field {required.name}")
        try:
            mode = Mode(by_tag[int(HelloTag.MODE)][0])
        except (ValueError, IndexError):
            raise malformed("invalid mode") from None
        content_type = by_tag[int(HelloTag.CONTENT_TYPE)].decode("ascii")
        method = (
            by_tag[int(HelloTag.METHOD)].decode("ascii") if int(HelloTag.METHOD) in by_tag else ""
        )
        deadline_ms = (
            _U32.unpack(by_tag[int(HelloTag.DEADLINE_MS)])[0]
            if int(HelloTag.DEADLINE_MS) in by_tag
            else 0
        )
        correlation_id = by_tag.get(int(HelloTag.CORRELATION_ID), b"")
        traceparent = (
            by_tag[int(HelloTag.TRACE_PARENT)].decode("ascii")
            if int(HelloTag.TRACE_PARENT) in by_tag
            else ""
        )
        idempotency_key = by_tag.get(int(HelloTag.IDEMPOTENCY_KEY), b"")
        accept_raw = by_tag.get(int(HelloTag.ACCEPT_TYPES), b"")
        accept = tuple(accept_raw.decode("ascii").split(",")) if accept_raw else ()
        schema_id = (
            by_tag[int(HelloTag.SCHEMA_ID)].decode("ascii")
            if int(HelloTag.SCHEMA_ID) in by_tag
            else ""
        )
        priority = by_tag[int(HelloTag.PRIORITY)][0] if int(HelloTag.PRIORITY) in by_tag else 0

        initial_credit = (
            by_tag[int(HelloTag.INITIAL_CREDIT)][0] if int(HelloTag.INITIAL_CREDIT) in by_tag else 0
        )

        hello = cls(
            mode=mode,
            method=method,
            content_type=content_type,
            deadline_ms=deadline_ms,
            correlation_id=correlation_id,
            traceparent=traceparent,
            idempotency_key=idempotency_key,
            accept_types=accept,
            schema_id=schema_id,
            priority=priority,
            initial_credit=initial_credit,
            extensions=tuple(ext),
        )
        if hello.encode(registry) != raw:
            raise malformed("non-canonical ChannelHello")

        return hello
    