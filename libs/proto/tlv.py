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
import enum
from libs.proto.status import Status, error, malformed


class MsgType(enum.IntEnum):
    DATA = 1
    END = 2
    ERROR = 3
    CONTROL = 4
    CREDIT = 5


class Scope(enum.Flag):
    HELLO = enum.auto()        # ChannelHello extensions
    MESSAGE = enum.auto()      # DATA envelopes (first fragment)
    TRAILER = enum.auto()      # END / ERROR envelopes


_SCOPE_FOR = {MsgType.DATA: Scope.MESSAGE,
              MsgType.END: Scope.TRAILER,
              MsgType.ERROR: Scope.TRAILER}


def scope_for(mt: MsgType) -> Scope:
    return _SCOPE_FOR[mt]

__all__ = [
    "MsgType",
    "TLVEntry",
    "TLV_CRITICAL",
    "TLV_NONE",

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
