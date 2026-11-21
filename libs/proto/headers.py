from __future__ import annotations

from dataclasses import dataclass
import struct
from types import MappingProxyType
from typing import Callable, Iterable, Optional


from libs.proto.status import ProtocolError, Status, malformed, error
from libs.proto.tlv import TLVEntry, TLV_NONE, TLV_CRITICAL


__all__ = [
    "HeaderSpec",
    "HeaderRegistry",
]

_TLV = struct.Struct(">HBH")


@dataclass(frozen=True, slots=True)
class HeaderSpec:
    tag: int
    min_bytes: int = 0
    max_bytes: int = 0xFFFF
    must_be_critical: bool = False
    # None = valid in any envelope context
    contexts: frozenset[int] | None = None

    def __post_init__(self) -> None:
        if not 1 <= int(self.tag) <= 0xFFFF:
            raise ValueError("tag")
        if not 0 <= self.min_bytes <= self.max_bytes <= 0xFFFF:
            raise ValueError("length bounds")


class HeaderRegistry:
    """Immutable mapping of tag => HeaderSpec. Extendable via extend()."""

    __slots__ = ("_specs",)

    def __init__(self, specs: Iterable[HeaderSpec] = ()) -> None:
        by_tag: dict[int, HeaderSpec] = {}
        for spec in specs:
            if not isinstance(spec, HeaderSpec) or spec.tag in by_tag:
                raise ValueError("invalid or duplicate HeaderSpec")
            by_tag[spec.tag] = spec
        self._specs = MappingProxyType(by_tag)

    def extend(self, *specs: HeaderSpec) -> HeaderRegistry:
        """Return a new registry with the given specs appended.
        App tags must be >= 0x1000 (core is < 0x1000)."""
        for spec in specs:
            if spec.tag < 0x1000:
                raise ValueError("application tags must be >= 0x1000")
        return HeaderRegistry((*self._specs.values(), *specs))

    def _validate(self, entry: TLVEntry, context: int | None) -> None:
        spec = self._specs.get(entry.tag)
        if spec is None:
            if entry.critical:
                raise error(
                    Status.UNIMPLEMENTED,
                    f"unknown critical header 0x{int(entry.tag):04x}",
                )
            return
        if not spec.min_bytes <= len(entry.value) <= spec.max_bytes:
            raise malformed(f"invalid length for header 0x{entry.tag:04x}")
        if spec.must_be_critical and not entry.critical:
            raise malformed(f"header 0x{entry.tag:04x} must be critical")
        if spec.contexts is not None and context not in spec.contexts:
            raise malformed(f"header 0x{entry.tag:04x} in wrong envelope")

    def encode(
        self,
        fields: Iterable[TLVEntry],
        *,
        max_bytes: int,
        max_fields: int,
        context: int | None = None,
    ) -> bytes:
        ordered = sorted(fields, key=lambda e: e.tag)
        if len(ordered) > max_fields:
            raise malformed("too many headers")
        raw = bytearray()
        previous = 0
        for entry in ordered:
            if not isinstance(entry, TLVEntry):
                raise TypeError("TLVEntry required")
            if entry.tag <= previous:
                raise malformed("duplicate or unsorted header")
            previous = entry.tag
            self._validate(entry, context)
            raw += _TLV.pack(
                entry.tag,
                TLV_CRITICAL if entry.critical else TLV_NONE,
                len(entry.value),
            )
            raw += entry.value
            if len(raw) > max_bytes:
                raise malformed("header section too large")
        return bytes(raw)

    def decode(
        self,
        raw: bytes,
        *,
        max_bytes: int,
        max_fields: int,
        context: int | None = None,
    ) -> tuple[TLVEntry, ...]:
        if type(raw) is not bytes or len(raw) > max_bytes:
            raise malformed("header section too large")
        out: list[TLVEntry] = []
        previous = 0
        offset = 0
        while offset < len(raw):
            if len(raw) - offset < _TLV.size:
                raise malformed("truncated TLV")
            tag, flags, length = _TLV.unpack_from(raw, offset)
            offset += _TLV.size
            if flags & ~TLV_CRITICAL:
                raise malformed("undefined TLV flags")
            if tag <= previous:
                raise malformed("duplicate or unsorted header")
            previous = tag
            if length > len(raw) - offset:
                raise malformed("truncated TLV value")
            entry = TLVEntry(
                tag,
                raw[offset : offset + length],
                bool(flags & TLV_CRITICAL),
            )
            offset += length
            self._validate(entry, context)
            out.append(entry)
            if len(out) > max_fields:
                raise malformed("too many headers")
        return tuple(out)
