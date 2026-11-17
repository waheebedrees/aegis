"""Fragmentation and bounded reassembly (spec §3.2).

Invariants (all enforced, all fail-closed):
  * Headers appear only on the first fragment.
  * Control/terminal envelopes never interrupt a partial message.
  * Total accumulated size <= max_message_bytes.
  * Fragment count <= max_fragments.
  * A partial message at FIN is MALFORMED.
  * COMPRESSED is rejected until implemented.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from libs.proto.envelope import (
    MAX_HDR_BYTES,
    MESSAGE_REGISTRY,
    PREFIX_LEN,
    Envelope,
    MsgFlag,
    MsgType,
)
from libs.proto.status import ProtocolError, Status, malformed
from libs.proto.tlv import TLVEntry

__all__ = [
    "Message",
    "Fragmenter",
    "Reassembler",
    "DEFAULT_MAX_MESSAGE_BYTES",
    "DEFAULT_MAX_FRAGMENTS",
    "HARD_MAX_MESSAGE_BYTES",
]

DEFAULT_MAX_MESSAGE_BYTES = 4 * 1024 * 1024
HARD_MAX_MESSAGE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FRAGMENTS = 1024


@dataclass(frozen=True, slots=True)
class Message:
    data: bytes
    headers: tuple[TLVEntry, ...] = ()


class Fragmenter:
    """Splits a logical message into DATA envelopes."""

    __slots__ = ("max_chunk_bytes",)

    def __init__(self, max_chunk_bytes: int) -> None:
        from libs.proto.envelope import MAX_ENVELOPE_BYTES

        if not PREFIX_LEN + 64 <= max_chunk_bytes <= MAX_ENVELOPE_BYTES:
            raise ValueError("max_chunk_bytes out of bounds")
        self.max_chunk_bytes = max_chunk_bytes

    def fragment(
        self,
        data: bytes,
        headers: tuple[TLVEntry, ...] = (),
    ) -> Iterator[Envelope]:
        if type(data) is not bytes:
            raise ProtocolError(Status.INVALID_ARGUMENT, "data must be bytes")
        hdr_bytes = (
            MESSAGE_REGISTRY.encode(
                headers, max_bytes=MAX_HDR_BYTES, max_fields=32, context=int(MsgType.DATA)
            )
            if headers
            else b""
        )
        first_overhead = PREFIX_LEN + len(hdr_bytes)
        if first_overhead >= self.max_chunk_bytes:
            raise ProtocolError(Status.INVALID_ARGUMENT, "headers too large")
        first_cap = self.max_chunk_bytes - first_overhead
        subseq_cap = self.max_chunk_bytes - PREFIX_LEN
        if len(data) <= first_cap:
            yield Envelope(MsgType.DATA, headers=headers, payload=data)
            return
        yield Envelope(
            MsgType.DATA,
            headers=headers,
            payload=data[:first_cap],
            flags=MsgFlag.FRAG_MORE,
        )
        offset = first_cap
        while offset < len(data):
            end = min(offset + subseq_cap, len(data))
            more = end < len(data)
            yield Envelope(
                MsgType.DATA,
                headers=(),
                payload=data[offset:end],
                flags=MsgFlag.FRAG_MORE if more else MsgFlag.NONE,
            )
            offset = end


class Reassembler:
    """At most one logical message under construction per instance."""

    __slots__ = (
        "max_message_bytes",
        "max_fragments",
        "_buf",
        "_headers",
        "_count",
        "_poisoned",
    )

    def __init__(
        self,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        max_fragments: int = DEFAULT_MAX_FRAGMENTS,
    ) -> None:
        if not 1 <= max_message_bytes <= HARD_MAX_MESSAGE_BYTES:
            raise ValueError("max_message_bytes out of bounds")
        if not 1 <= max_fragments <= 65536:
            raise ValueError("max_fragments out of bounds")
        self.max_message_bytes = max_message_bytes
        self.max_fragments = max_fragments
        self._buf = bytearray()
        self._headers: tuple[TLVEntry, ...] = ()
        self._count = 0
        self._poisoned = False

    @property
    def in_progress(self) -> bool:
        return self._count > 0

    def _fail(self, status: Status, detail: str) -> None:
        self._buf.clear()
        self._headers = ()
        self._count = 0
        self._poisoned = True
        raise ProtocolError(status, detail)

    def check_no_partial(self, context: str = "non-DATA envelope") -> None:
        if self._poisoned:
            raise malformed("reassembler poisoned")
        if self._count > 0:
            self._fail(Status.MALFORMED, f"partial interrupted by {context}")

    def feed(self, env: Envelope) -> Message | None:
        if self._poisoned:
            raise malformed("reassembler poisoned")
        if env.type is not MsgType.DATA:
            self._fail(Status.MALFORMED, f"expected DATA, got {env.type.name}")
        if env.flags & MsgFlag.COMPRESSED:
            raise ProtocolError(Status.UNIMPLEMENTED, "COMPRESSED unsupported")
        more = bool(env.flags & MsgFlag.FRAG_MORE)
        if self._count == 0:
            if not more:
                if len(env.payload) > self.max_message_bytes:
                    self._fail(Status.RESOURCE_EXHAUSTED, "message too large")
                return Message(env.payload, env.headers)
            if not env.payload:
                self._fail(Status.MALFORMED, "empty intermediate fragment")
            self._count = 1
            self._headers = env.headers
            self._buf.extend(env.payload)
            return None
        if env.headers:
            self._fail(Status.MALFORMED, "continuation with headers")
        if more and not env.payload:
            self._fail(Status.MALFORMED, "empty intermediate fragment")
        self._count += 1
        if self._count > self.max_fragments:
            self._fail(Status.RESOURCE_EXHAUSTED, "fragment count exceeded")
        if len(self._buf) + len(env.payload) > self.max_message_bytes:
            self._fail(Status.RESOURCE_EXHAUSTED, "message too large")
        self._buf.extend(env.payload)
        if more:
            return None
        data = bytes(self._buf)
        headers = self._headers
        self._buf.clear()
        self._headers = ()
        self._count = 0
        return Message(data, headers)
