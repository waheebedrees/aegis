"""TLV codec and header registry (spec §4 axis 3).

Wire form: u16 tag | u8 flags | u16 len | value
  tag   0x0001..0xFFFF (0 reserved)
  flags bit 0 = CRITICAL; other bits reserved
  TLVs on the wire must be strictly ascending by tag

HeaderSpec gives every known tag a length bound, optional criticality,
and optional envelope-context set. Unknown non-critical tags are
preserved; unknown critical tags fail closed. Apps extend a registry
with HeaderRegistry.extend() using tags >= 0x1000.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from types import MappingProxyType

from libs.proto.status import Status, error, malformed

__all__ = [
    "TLVEntry",
    "TLV_CRITICAL",
    "TLV_NONE",
    "HeaderSpec",
    "HeaderRegistry",
]

_TLV = struct.Struct(">HBH")
TLV_HEADER_LEN = _TLV.size  # 5

TLV_CRITICAL = 0x01
TLV_NONE = 0x00

_MAX_VALUE = 0xFFFF


@dataclass(frozen=True, slots=True)
class TLVEntry:
    tag: int
    value: bytes
    critical: bool = False

    @property
    def flags(self) -> bool:
        return bool(self.critical & TLV_CRITICAL)

    def __post_init__(self) -> None:
        if not 1 <= int(self.tag) <= 0xFFFF:
            raise ValueError("tag must be 1..65535")
        if type(self.value) is not bytes or len(self.value) > 0xFFFF:
            raise ValueError("value must be bytes <= 65535")
        if type(self.critical) is not bool:
            raise ValueError("critical must be bool")


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


def make_tlv(tag: int, value: bytes, *, critical: bool = False) -> TLVEntry:
    return TLVEntry(int(tag), critical=bool(TLV_CRITICAL if critical else TLV_NONE), value=value)


def encode_tlvs(entries: Mapping[int, TLVEntry] | Sequence[TLVEntry]) -> bytes:
    items = list(entries.values()) if isinstance(entries, Mapping) else list(entries)
    if not items:
        return b""

    norm: list[tuple[int, int, bytes]] = []
    for e in items:
        if not isinstance(e, TLVEntry):
            raise error(Status.INTERNAL, "TLVEntry required")
        tag = int(e.tag)
        if not 1 <= tag <= 0xFFFF:
            raise error(Status.MALFORMED, f"invalid tag {tag}")
        flags = int(e.flags)
        if flags & ~TLV_CRITICAL:
            raise error(Status.MALFORMED, f"bad flags on 0x{tag:04x}")
        if type(e.value) is not bytes:
            raise error(Status.MALFORMED, f"tag 0x{tag:04x} value must be bytes")
        if len(e.value) > _MAX_VALUE:
            raise error(Status.OUT_OF_RANGE, f"tag 0x{tag:04x} value too large")
        norm.append((tag, flags, e.value))

    norm.sort(key=lambda x: x[0])
    seen: set[int] = set()
    out: list[bytes] = []
    for tag, flags, value in norm:
        if tag in seen:
            raise error(Status.MALFORMED, f"duplicate tag 0x{tag:04x}")
        seen.add(tag)
        out.append(_TLV.pack(tag, flags, len(value)))
        out.append(value)
    return b"".join(out)


def decode_tlvs(
    data: bytes,
    *,
    known_tags: AbstractSet[int] = frozenset(),
) -> dict[int, TLVEntry]:
    if type(data) is not bytes:
        raise error(Status.MALFORMED, "TLV data must be bytes")

    out: dict[int, TLVEntry] = {}
    prev_tag = -1
    i, n = 0, len(data)
    while i < n:
        if i + TLV_HEADER_LEN > n:
            raise error(Status.MALFORMED, "truncated TLV header")
        tag, flags, length = _TLV.unpack_from(data, i)
        i += TLV_HEADER_LEN

        if tag == 0:
            raise error(Status.MALFORMED, "reserved tag 0x0000")
        if flags & ~TLV_CRITICAL:
            raise error(Status.MALFORMED, f"tag 0x{tag:04x} has unknown flags 0x{flags:02x}")
        if length > n - i:
            raise error(Status.MALFORMED, f"truncated value for tag 0x{tag:04x}")
        if tag <= prev_tag:
            raise error(Status.MALFORMED, f"tag 0x{tag:04x} out of order")
        prev_tag = tag

        value = data[i : i + length]
        i += length

        is_crit = bool(flags & TLV_CRITICAL)
        if is_crit and tag not in known_tags:
            raise error(Status.UNIMPLEMENTED, f"unknown critical tag 0x{tag:04x}")

        out[tag] = TLVEntry(tag, value, bool(flags))
    return out
