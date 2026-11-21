"""typed binary payload codec.
Frozen dataclasses in, deterministic bytes out, strict bounds at every field.
Wire format documented in the docstring. Rejects float / dict / set / Any by
design — no NaN, no dict ordering, no round-trip ambiguity.
"""

from __future__ import annotations

import dataclasses
import hashlib
import struct
from collections.abc import Callable
from types import UnionType
from typing import (
    Any,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

__all__ = [
    "CodecError",
    "encode",
    "decode",
    "schema_digest",
    "MAX_STR",
    "MAX_BYTES",
    "MAX_TUPLE",
    "MAX_NESTING",
]

MAX_STR = 64 * 1024
MAX_BYTES = 4 * 1024 * 1024
MAX_TUPLE = 1024
MAX_NESTING = 8

I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
_U32 = struct.Struct(">I")
_I64 = struct.Struct(">q")
_DOMAIN = b"aegis-codec-v1\x00"


class CodecError(Exception):
    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True, slots=True)
class _Compiled:
    encode: Callable[[Any], bytes]
    decode: Callable[[bytes, int], tuple[Any, int]]
    digest: bytes


_CACHE: dict[type, _Compiled] = {}


def _compile(tp: type) -> _Compiled:
    c = _CACHE.get(tp)
    if c is not None:
        return c
    c = _compile_object(tp, depth=0)
    _CACHE[tp] = c
    return c


def encode(obj: Any) -> bytes:
    if obj is None:
        raise CodecError("NONE")
    return _compile(type(obj)).encode(obj)


def decode(cls: type, raw: bytes) -> Any:
    if type(raw) is not bytes:
        raise CodecError("BAD_INPUT", type(raw).__name__)
    c = _compile(cls)
    val, off = c.decode(raw, 0)
    if off != len(raw):
        raise CodecError("TRAILING", f"{len(raw) - off} bytes")
    return val


def schema_digest(cls: type) -> bytes:
    return _compile(cls).digest


def _compile_object(cls: type, depth: int) -> _Compiled:
    if not isinstance(cls, type) or not dataclasses.is_dataclass(cls):
        raise CodecError("NOT_DATACLASS", repr(cls))
    if not cls.__dataclass_params__.frozen:
        raise CodecError("NOT_FROZEN", cls.__name__)

    try:
        hints = get_type_hints(cls)
    except Exception as exc:
        raise CodecError("HINTS", f"{cls.__name__}: {exc}") from None

    parts: list[tuple[str, Callable, Callable]] = []
    sigs: list[str] = []
    for f in dataclasses.fields(cls):
        if f.name not in hints:
            raise CodecError("NO_HINT", f"{cls.__name__}.{f.name}")
        enc, dec, sig = _compile_value(hints[f.name], depth)
        parts.append((f.name, enc, dec))
        sigs.append(f"{f.name}:{sig}")

    def enc(obj: Any) -> bytes:
        if type(obj) is not cls:
            raise CodecError(
                "WRONG_TYPE",
                f"expected {cls.__name__}, got {type(obj).__name__}",
            )
        return b"".join(f_enc(getattr(obj, n)) for n, f_enc, _ in parts)

    def dec(raw: bytes, off: int) -> tuple[Any, int]:
        kwargs = {}
        for n, _, f_dec in parts:
            v, off = f_dec(raw, off)
            kwargs[n] = v
        return cls(**kwargs), off

    h = hashlib.sha256(_DOMAIN)
    h.update(cls.__name__.encode("utf-8") + b"\x00")
    for s in sigs:
        h.update(s.encode("ascii") + b"\x00")

    return _Compiled(enc, dec, h.digest())


def _compile_value(tp: Any, depth: int) -> tuple[Callable, Callable, str]:
    if depth > MAX_NESTING:
        raise CodecError("NESTING", str(depth))

    if tp is int:

        def e(v: Any) -> bytes:
            if type(v) is not int or not I64_MIN <= v <= I64_MAX:
                raise CodecError("BAD_INT")
            return _I64.pack(v)

        def d(raw: bytes, off: int) -> tuple[int, int]:
            if off + 8 > len(raw):
                raise CodecError("TRUNCATED", "int")
            return _I64.unpack_from(raw, off)[0], off + 8

        return e, d, "i64"

    if tp is bool:

        def e(v: Any) -> bytes:
            if type(v) is not bool:
                raise CodecError("BAD_BOOL")
            return b"\x01" if v else b"\x00"

        def d(raw: bytes, off: int) -> tuple[bool, int]:
            if off + 1 > len(raw):
                raise CodecError("TRUNCATED", "bool")
            b = raw[off]
            if b > 1:
                raise CodecError("BAD_BOOL")
            return bool(b), off + 1

        return e, d, "bool"

    if tp is str:

        def e(v: Any) -> bytes:
            if type(v) is not str:
                raise CodecError("BAD_STR")
            try:
                b = v.encode("utf-8")
            except UnicodeEncodeError:
                raise CodecError("BAD_STR_ENC") from None
            if len(b) > MAX_STR:
                raise CodecError("STR_TOO_LARGE", str(len(b)))
            return _U32.pack(len(b)) + b

        def d(raw: bytes, off: int) -> tuple[str, int]:
            if off + 4 > len(raw):
                raise CodecError("TRUNCATED", "str_len")
            n = _U32.unpack_from(raw, off)[0]
            off += 4
            if n > MAX_STR:
                raise CodecError("STR_TOO_LARGE", str(n))
            if off + n > len(raw):
                raise CodecError("TRUNCATED", "str_data")
            try:
                s = raw[off : off + n].decode("utf-8")
            except UnicodeDecodeError:
                raise CodecError("BAD_STR_ENC") from None
            return s, off + n

        return e, d, "str"

    if tp is bytes:

        def e(v: Any) -> bytes:
            if type(v) is not bytes:
                raise CodecError("BAD_BYTES")
            if len(v) > MAX_BYTES:
                raise CodecError("BYTES_TOO_LARGE", str(len(v)))
            return _U32.pack(len(v)) + v

        def d(raw: bytes, off: int) -> tuple[bytes, int]:
            if off + 4 > len(raw):
                raise CodecError("TRUNCATED", "bytes_len")
            n = _U32.unpack_from(raw, off)[0]
            off += 4
            if n > MAX_BYTES:
                raise CodecError("BYTES_TOO_LARGE", str(n))
            if off + n > len(raw):
                raise CodecError("TRUNCATED", "bytes_data")
            return raw[off : off + n], off + n

        return e, d, "bytes"

    origin, args = get_origin(tp), get_args(tp)

    if origin in (Union, UnionType) and len(args) == 2 and type(None) in args:
        inner = args[0] if args[1] is type(None) else args[1]
        ie, id_, isig = _compile_value(inner, depth + 1)

        def e(v: Any) -> bytes:
            return b"\x00" if v is None else b"\x01" + ie(v)

        def d(raw: bytes, off: int) -> tuple[Any, int]:
            if off + 1 > len(raw):
                raise CodecError("TRUNCATED", "opt")
            b = raw[off]
            if b == 0:
                return None, off + 1
            if b != 1:
                raise CodecError("BAD_OPT")
            return id_(raw, off + 1)

        return e, d, f"opt<{isig}>"

    if origin is tuple and len(args) == 2 and args[1] is Ellipsis:
        ie, id_, isig = _compile_value(args[0], depth + 1)

        def e(v: Any) -> bytes:
            if type(v) is not tuple:
                raise CodecError("BAD_TUPLE")
            if len(v) > MAX_TUPLE:
                raise CodecError("TUPLE_TOO_LARGE", str(len(v)))
            return _U32.pack(len(v)) + b"".join(ie(x) for x in v)

        def d(raw: bytes, off: int) -> tuple[tuple, int]:
            if off + 4 > len(raw):
                raise CodecError("TRUNCATED", "tuple_len")
            n = _U32.unpack_from(raw, off)[0]
            off += 4
            if n > MAX_TUPLE:
                raise CodecError("TUPLE_TOO_LARGE", str(n))
            items = []
            for _ in range(n):
                v, off = id_(raw, off)
                items.append(v)
            return tuple(items), off

        return e, d, f"tuple<{isig}>"

    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        sub = _compile_object(tp, depth + 1)
        return sub.encode, sub.decode, f"obj<{sub.digest.hex()}>"

    raise CodecError("UNSUPPORTED_TYPE", repr(tp))
