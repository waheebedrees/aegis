"""Security invariants (all codecs):
* encoded size  <= CodecLimits.max_bytes
* nesting depth <= CodecLimits.max_depth  (linear pre-scan, defeats bombs)
* total items   <= CodecLimits.max_items
* NaN / ±Inf    rejected unless limits.allow_nan
* CBOR additionally rejects: indefinite-length, unknown tags/simple values,
  reserved additional-info codes, length headers exceeding remaining bytes,
  duplicate map keys, trailing bytes, non-finite floats.
"""

import json
import math
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from libs.proto.status import ProtocolError, Status

__all__ = [
    "CodecLimits",
    "Codec",
    "RawCodec",
    "JsonCodec",
    "CborCodec",
    "CodecRegistry",
    "default_codecs",
    "DEFAULT_CODECS",
]

_U8 = struct.Struct(">B")
_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")
_U64 = struct.Struct(">Q")
_F16 = struct.Struct(">e")
_F32 = struct.Struct(">f")
_F64 = struct.Struct(">d")

_UINT64_MAX = (1 << 64) - 1
_NINT64_MIN = -(1 << 64)
_MAX_HARD_BYTES = 16 * 1024 * 1024
_MAX_HARD_DEPTH = 128
_MAX_HARD_ITEMS = 1_000_000


@dataclass(frozen=True, slots=True)
class CodecLimits:
    max_bytes: int = 48 * 1024
    max_depth: int = 32
    max_items: int = 4096
    allow_nan: bool = False
    allow_int_keys: bool = True

    def __post_init__(self) -> None:
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= _MAX_HARD_BYTES:
            raise ValueError("max_bytes out of bounds")
        if type(self.max_depth) is not int or not 1 <= self.max_depth <= _MAX_HARD_DEPTH:
            raise ValueError("max_depth out of bounds")
        if type(self.max_items) is not int or not 1 <= self.max_items <= _MAX_HARD_ITEMS:
            raise ValueError("max_items out of bounds")


@runtime_checkable
class Codec(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def content_type(self) -> str: ...
    def encode(self, value: Any, schema_id: str = "") -> bytes: ...
    def decode(self, data: bytes, schema_id: str = "") -> Any: ...


# ── RawCodec ──────────────────────────────────────────────────────────────


class RawCodec:
    __slots__ = ("_limits",)

    def __init__(self, limits: CodecLimits = CodecLimits()) -> None:
        self._limits = limits

    @property
    def name(self) -> str:
        return "raw"

    @property
    def content_type(self) -> str:
        return "application/octet-stream"

    def encode(self, value: Any, schema_id: str = "") -> bytes:
        if type(value) is not bytes:
            raise ProtocolError(
                Status.INVALID_ARGUMENT, f"raw expects bytes, got {type(value).__name__}"
            )
        if len(value) > self._limits.max_bytes:
            raise ProtocolError(Status.OUT_OF_RANGE, str(len(value)))
        return value

    def decode(self, data: bytes, schema_id: str = "") -> bytes:
        if type(data) is not bytes:
            raise ProtocolError(Status.MALFORMED, "raw input must be bytes")
        if len(data) > self._limits.max_bytes:
            raise ProtocolError(Status.OUT_OF_RANGE, str(len(data)))
        return data


# ── JsonCodec ─────────────────────────────────────────────────────────────


def _check_json_depth(text: str, max_depth: int) -> None:
    """Linear pre-scan that defeats bracket-nesting RecursionError bombs."""
    depth = 0
    in_str = False
    escape = False
    for ch in text:
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch in "[{":
                depth += 1
                if depth > max_depth:
                    raise ProtocolError(Status.OUT_OF_RANGE, f"json depth {depth} > {max_depth}")
            elif ch in "]}":
                depth -= 1
                if depth < 0:
                    raise ProtocolError(Status.MALFORMED, "unbalanced json")
    if depth != 0:
        raise ProtocolError(Status.MALFORMED, "unbalanced json")


def _validate_json_tree(value: Any, *, limits: CodecLimits, depth: int, counter: list[int]) -> None:
    t = type(value)
    if value is None or t is bool or t is str:
        return
    if t is int:
        if not _NINT64_MIN <= value <= _UINT64_MAX:
            raise ProtocolError(Status.OUT_OF_RANGE, "json int range")
        return
    if t is float:
        if not limits.allow_nan and not math.isfinite(value):
            raise ProtocolError(Status.INVALID_ARGUMENT, "json non-finite float")
        return
    if t in (list, tuple):
        if depth >= limits.max_depth:
            raise ProtocolError(Status.OUT_OF_RANGE, "json depth")
        counter[0] += len(value)
        if counter[0] > limits.max_items:
            raise ProtocolError(Status.OUT_OF_RANGE, "json item limit")
        for elem in value:
            _validate_json_tree(elem, limits=limits, depth=depth + 1, counter=counter)
        return
    if t is dict:
        if depth >= limits.max_depth:
            raise ProtocolError(Status.OUT_OF_RANGE, "json depth")
        counter[0] += len(value)
        if counter[0] > limits.max_items:
            raise ProtocolError(Status.OUT_OF_RANGE, "json item limit")
        for k, v in value.items():
            if type(k) is not str:
                raise ProtocolError(Status.INVALID_ARGUMENT, "json key must be str")
            _validate_json_tree(v, limits=limits, depth=depth + 1, counter=counter)
        return
    raise ProtocolError(Status.INVALID_ARGUMENT, f"json cannot encode {t.__name__}")


class JsonCodec:
    __slots__ = ("_limits",)

    def __init__(self, limits: CodecLimits = CodecLimits()) -> None:
        self._limits = limits

    @property
    def name(self) -> str:
        return "json"

    @property
    def content_type(self) -> str:
        return "application/json"

    def encode(self, value: Any, schema_id: str = "") -> bytes:
        _validate_json_tree(value, limits=self._limits, depth=0, counter=[0])
        try:
            raw = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=self._limits.allow_nan,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ProtocolError(
                Status.INVALID_ARGUMENT, f"json encode: {type(exc).__name__}"
            ) from None
        if len(raw) > self._limits.max_bytes:
            raise ProtocolError(Status.OUT_OF_RANGE, f"json {len(raw)}B")
        return raw

    def decode(self, data: bytes, schema_id: str = "") -> Any:
        if type(data) is not bytes:
            raise ProtocolError(Status.MALFORMED, "json input must be bytes")
        if len(data) > self._limits.max_bytes:
            raise ProtocolError(Status.OUT_OF_RANGE, f"json {len(data)}B")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ProtocolError(Status.MALFORMED, "json bad utf8") from None
        _check_json_depth(text, self._limits.max_depth)

        def _reject_const(token: str) -> Any:
            if not self._limits.allow_nan:
                raise ProtocolError(Status.INVALID_ARGUMENT, f"json {token}")
            return float(token)

        def _no_dup(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for k, v in pairs:
                if k in out:
                    raise ProtocolError(Status.MALFORMED, f"json dup key {k[:32]}")
                out[k] = v
            return out

        try:
            obj = json.loads(text, parse_constant=_reject_const, object_pairs_hook=_no_dup)
        except ProtocolError:
            raise
        except json.JSONDecodeError:
            raise ProtocolError(Status.MALFORMED, "json malformed") from None
        except RecursionError:
            raise ProtocolError(Status.OUT_OF_RANGE, "json depth") from None
        _validate_json_tree(obj, limits=self._limits, depth=0, counter=[0])
        return obj


# ── CborCodec (RFC 8949, deterministic encoding) ──────────────────────────


def _pack_head(major: int, val: int) -> bytes:
    mt = major << 5
    if val < 24:
        return _U8.pack(mt | val)
    if val <= 0xFF:
        return _U8.pack(mt | 24) + _U8.pack(val)
    if val <= 0xFFFF:
        return _U8.pack(mt | 25) + _U16.pack(val)
    if val <= 0xFFFFFFFF:
        return _U8.pack(mt | 26) + _U32.pack(val)
    if val <= _UINT64_MAX:
        return _U8.pack(mt | 27) + _U64.pack(val)
    raise ProtocolError(Status.OUT_OF_RANGE, "cbor int too large")


class CborCodec:
    """Deterministic CBOR: shortest-form ints/lengths, sorted map keys,
    f64 floats, no indefinite-length. Decoder is strict and fail-closed."""

    __slots__ = ("_limits",)

    def __init__(self, limits: CodecLimits = CodecLimits()) -> None:
        self._limits = limits

    @property
    def name(self) -> str:
        return "cbor"

    @property
    def content_type(self) -> str:
        return "application/cbor"

    # ── encode ───────────────────────────────────────────────────────────

    def encode(self, value: Any, schema_id: str = "") -> bytes:
        out = bytearray()
        self._enc(value, out, depth=0, counter=[0])
        if len(out) > self._limits.max_bytes:
            raise ProtocolError(Status.OUT_OF_RANGE, f"cbor {len(out)}B")
        return bytes(out)

    def _enc(self, v: Any, out: bytearray, *, depth: int, counter: list[int]) -> None:
        if len(out) > self._limits.max_bytes:
            raise ProtocolError(Status.OUT_OF_RANGE, "cbor overflow")
        t = type(v)
        if v is None:
            out.append(0xF6)
            return
        if t is bool:
            out.append(0xF5 if v else 0xF4)
            return
        if t is int:
            if v >= 0:
                out += _pack_head(0, v)
            else:
                out += _pack_head(1, -1 - v)
            return
        if t is float:
            if not self._limits.allow_nan and not math.isfinite(v):
                raise ProtocolError(Status.INVALID_ARGUMENT, "cbor non-finite")
            out.append(0xFB)
            out += _F64.pack(v)
            return
        if t is bytes:
            out += _pack_head(2, len(v))
            out += v
            return
        if t is str:
            b = v.encode("utf-8")
            out += _pack_head(3, len(b))
            out += b
            return
        if t in (list, tuple):
            if depth >= self._limits.max_depth:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor depth")
            counter[0] += len(v)
            if counter[0] > self._limits.max_items:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor items")
            out += _pack_head(4, len(v))
            for elem in v:
                self._enc(elem, out, depth=depth + 1, counter=counter)
            return
        if t is dict:
            if depth >= self._limits.max_depth:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor depth")
            counter[0] += len(v)
            if counter[0] > self._limits.max_items:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor items")
            pairs: list[tuple[bytes, Any]] = []
            seen: set[bytes] = set()
            for k, val in v.items():
                if type(k) is str:
                    ek = _pack_head(3, len(k.encode("utf-8"))) + k.encode("utf-8")
                elif type(k) is int and self._limits.allow_int_keys:
                    if k >= 0:
                        ek = _pack_head(0, k)
                    else:
                        ek = _pack_head(1, -1 - k)
                else:
                    raise ProtocolError(Status.INVALID_ARGUMENT, f"cbor key {type(k).__name__}")
                if ek in seen:
                    raise ProtocolError(Status.INVALID_ARGUMENT, "cbor dup key")
                seen.add(ek)
                pairs.append((ek, val))
            pairs.sort(key=lambda p: p[0])
            out += _pack_head(5, len(pairs))
            for ek, val in pairs:
                out += ek
                self._enc(val, out, depth=depth + 1, counter=counter)
            return
        raise ProtocolError(Status.INVALID_ARGUMENT, f"cbor cannot encode {t.__name__}")

    # ── decode ───────────────────────────────────────────────────────────

    def decode(self, data: bytes, schema_id: str = "") -> Any:
        if type(data) is not bytes:
            raise ProtocolError(Status.MALFORMED, "cbor input must be bytes")
        if not data:
            raise ProtocolError(Status.MALFORMED, "cbor empty")
        if len(data) > self._limits.max_bytes:
            raise ProtocolError(Status.OUT_OF_RANGE, f"cbor {len(data)}B")
        val, off = self._dec(data, 0, depth=0, counter=[0])
        if off != len(data):
            raise ProtocolError(Status.MALFORMED, "cbor trailing bytes")
        return val

    @staticmethod
    def _read_arg(data: bytes, off: int, ai: int) -> tuple[int, int]:
        if ai < 24:
            return ai, off
        if ai == 24:
            if off + 1 > len(data):
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            return data[off], off + 1
        if ai == 25:
            if off + 2 > len(data):
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            return _U16.unpack_from(data, off)[0], off + 2
        if ai == 26:
            if off + 4 > len(data):
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            return _U32.unpack_from(data, off)[0], off + 4
        if ai == 27:
            if off + 8 > len(data):
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            return _U64.unpack_from(data, off)[0], off + 8
        if ai == 31:
            raise ProtocolError(Status.MALFORMED, "cbor indefinite")
        raise ProtocolError(Status.MALFORMED, f"cbor reserved ai={ai}")

    def _dec(self, data: bytes, off: int, *, depth: int, counter: list[int]) -> tuple[Any, int]:
        n = len(data)
        if off >= n:
            raise ProtocolError(Status.MALFORMED, "cbor truncated")
        ib = data[off]
        off += 1
        major = ib >> 5
        ai = ib & 0x1F

        if major == 0:
            v, off = self._read_arg(data, off, ai)
            return v, off
        if major == 1:
            v, off = self._read_arg(data, off, ai)
            return -1 - v, off
        if major == 2:
            length, off = self._read_arg(data, off, ai)
            if length > n - off:
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            return data[off : off + length], off + length
        if major == 3:
            length, off = self._read_arg(data, off, ai)
            if length > n - off:
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            try:
                return data[off : off + length].decode("utf-8"), off + length
            except UnicodeDecodeError:
                raise ProtocolError(Status.MALFORMED, "cbor bad utf8") from None
        if major == 4:
            if depth >= self._limits.max_depth:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor depth")
            length, off = self._read_arg(data, off, ai)
            if length > n - off:
                raise ProtocolError(Status.MALFORMED, "cbor trunc array")
            counter[0] += length
            if counter[0] > self._limits.max_items:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor items")
            arr: list[Any] = []
            for _ in range(length):
                v, off = self._dec(data, off, depth=depth + 1, counter=counter)
                arr.append(v)
            return arr, off
        if major == 5:
            if depth >= self._limits.max_depth:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor depth")
            length, off = self._read_arg(data, off, ai)
            if length * 2 > n - off:
                raise ProtocolError(Status.MALFORMED, "cbor trunc map")
            counter[0] += length
            if counter[0] > self._limits.max_items:
                raise ProtocolError(Status.OUT_OF_RANGE, "cbor items")
            mapping: dict[Any, Any] = {}
            seen: set[tuple[type, Any]] = set()
            for _ in range(length):
                k, off = self._dec(data, off, depth=depth + 1, counter=counter)
                kt = type(k)
                if not (kt is str or (kt is int and self._limits.allow_int_keys)):
                    raise ProtocolError(Status.INVALID_ARGUMENT, "cbor bad key")
                tag = (kt, k)
                if tag in seen:
                    raise ProtocolError(Status.MALFORMED, "cbor dup key")
                seen.add(tag)
                v, off = self._dec(data, off, depth=depth + 1, counter=counter)
                mapping[k] = v
            return mapping, off
        if major == 6:
            raise ProtocolError(Status.UNIMPLEMENTED, "cbor tags unsupported")
        # major == 7
        if ai == 20:
            return False, off
        if ai == 21:
            return True, off
        if ai == 22:
            return None, off
        if ai == 25:
            if off + 2 > n:
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            f = _F16.unpack_from(data, off)[0]
            if not self._limits.allow_nan and not math.isfinite(f):
                raise ProtocolError(Status.INVALID_ARGUMENT, "cbor non-finite")
            return f, off + 2
        if ai == 26:
            if off + 4 > n:
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            f = _F32.unpack_from(data, off)[0]
            if not self._limits.allow_nan and not math.isfinite(f):
                raise ProtocolError(Status.INVALID_ARGUMENT, "cbor non-finite")
            return f, off + 4
        if ai == 27:
            if off + 8 > n:
                raise ProtocolError(Status.MALFORMED, "cbor trunc")
            f = _F64.unpack_from(data, off)[0]
            if not self._limits.allow_nan and not math.isfinite(f):
                raise ProtocolError(Status.INVALID_ARGUMENT, "cbor non-finite")
            return f, off + 8
        if ai == 31:
            raise ProtocolError(Status.MALFORMED, "cbor indefinite")
        raise ProtocolError(Status.MALFORMED, f"cbor simple {ai}")


# ── CodecRegistry ─────────────────────────────────────────────────────────


class CodecRegistry:
    """Immutable-after-freeze table keyed by content_type."""

    __slots__ = ("_by_ct", "_by_name", "_frozen")

    def __init__(self, codecs: Iterable[Codec] = ()) -> None:
        self._by_ct: dict[str, Codec] = {}
        self._by_name: dict[str, Codec] = {}
        self._frozen = False
        for c in codecs:
            self.register(c)

    def register(self, codec: Codec) -> None:
        if self._frozen:
            raise ProtocolError(Status.FAILED_PRECONDITION, "codec registry frozen")
        if not isinstance(codec, Codec):
            raise TypeError("codec must implement Codec")
        ct = codec.content_type
        if not isinstance(ct, str) or not ct or not ct.isascii():
            raise ValueError("content_type must be non-empty ASCII")
        if ct in self._by_ct:
            raise ValueError(f"duplicate codec: {ct}")
        self._by_ct[ct] = codec
        self._by_name[codec.name] = codec

    def get(self, content_type: str) -> Codec:
        codec = self._by_ct.get(content_type)
        if codec is None:
            raise ProtocolError(Status.UNAVAILABLE, "unknown codec type ")
        return codec

    def get_by_name(self, name: str) -> Codec:
        codec = self._by_name.get(name)
        if codec is None:
            raise ProtocolError(Status.UNAVAILABLE, "unknown codec type ")
        return codec

    def require(self, content_type: str) -> Codec:
        c = self._by_ct.get(content_type)
        if c is None:
            raise ProtocolError(Status.UNSUPPORTED_MEDIA, f"no codec for {content_type!r}"[:80])
        return c

    def content_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_ct))

    def freeze(self) -> "CodecRegistry":
        self._frozen = True
        return self

    def __len__(self) -> int:
        return len(self._by_ct)

    def __contains__(self, ct: object) -> bool:
        return isinstance(ct, str) and ct in self._by_ct


def default_codecs(limits: CodecLimits = CodecLimits()) -> CodecRegistry:
    return CodecRegistry((RawCodec(limits), JsonCodec(limits), CborCodec(limits)))


DEFAULT_CODECS = default_codecs().freeze()
