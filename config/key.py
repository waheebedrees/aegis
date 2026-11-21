from __future__ import annotations
import base64
import enum
import re
import tomllib
from typing import Literal
from pathlib import Path
import hashlib
import datetime as dt
from collections.abc import Iterable, Mapping
from typing import Any
import io
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, field_validator

schema = ["raw_b64", "hex", "tagged1"]
PATH_HINTS = (".pub", ".seed", ".key", ".bin")

KEY_BYTES = 32
SEED_BYTES = 32
_B54_PREFIX = "base64:"


def log(**kwargs):
    print(f"{kwargs}")


_PEER_NAME = re.compile(r"[a-z][a-z0-9._-]{0,31}")


def _host_port(t: Mapping[str, Any], where: str) -> tuple[str, int]:
    return (
        text(t["host"], f"{where}.host", 253),
        integer(t["port"], f"{where}.port", 1, 65535),
    )


def _spiffe(value: Any, where: str, *, pattern: bool = False) -> str:
    s = text(value, where)
    if not s.startswith("spiffe://") or len(s) <= len("spiffe://"):
        raise ConfigError(f"{where}: expected a spiffe:// identity")
    if any(c.isspace() for c in s) or "/../" in s or "/./" in s or s.endswith(("/..", "/.")):
        raise ConfigError(f"{where}: illegal path segment")
    stars = s.count("*")
    if stars and not (pattern and stars == 1 and s.endswith("/*")):
        raise ConfigError(f"{where}: wildcard only allowed as a trailing '/*' in patterns")
    return s


class ConfigError(Exception):
    """Invalid configuration.

    At startup: refuse to start.
    On reload:  keep the previous version and log.
    """


def _require_32(raw: bytes) -> bytes:
    if len(raw) != KEY_BYTES:
        raise ValueError(f"ed25519 public key must be {KEY_BYTES} bytes, got {len(raw)}")
    return raw


def _decode_inline(s: str, where: str) -> bytes:

    if s.startswith(_B54_PREFIX):
        s = s[len(_B54_PREFIX) :]

    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            return _require_32(bytes.fromhex(s))
        except ValueError:
            pass
    core = s.rstrip("=")
    padded = core + "=" * (-len(core) % 4)
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return _require_32(decode(padded))
        except Exception:
            continue

    raise ValueError(
        f"{where}: cannot decode as b64 (urlsafe or standard) or hex "
        f"({len(s)} chars after stripping tags)"
    )


def file_path(path: Path | str, *, base: Path | str | None = None, must_exist: bool = True) -> Path:

    path = Path(str(path))
    path = path.resolve()
    if base:
        base = Path(base)
        if not path.is_absolute():
            path = base / path
    path = path.resolve()
    if must_exist and not (path.is_file() or path.exists()):
        raise ValueError(f"file not found: {path}")
    return path


def load_file(source: str | bytes | Path, base: Path | str | None = None) -> bytes:
    if isinstance(source, bytes):
        return _require_32(source)

    s = str(source)
    look_like_path = isinstance(source, Path) or s.endswith(PATH_HINTS) or "/" in s or "\\" in s

    if look_like_path:
        p = file_path(s, base=base)
        raw = p.read_bytes()
        if len(raw) == KEY_BYTES:
            return raw

        try:
            t = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ValueError(
                f"{p}: not a raw {KEY_BYTES}-byte key (file is {len(raw)} bytes, not ASCII)"
            ) from None

        return _decode_inline(t, where=str(p))

    return _decode_inline(s.strip(), where="<inline>")


def load_seed(source: str | bytes | Path, base: Path | str | None = None) -> bytes:
    raw = load_file(source, base=base)
    if len(raw) != SEED_BYTES:
        raise ValueError(f"seed must be {SEED_BYTES} bytes, got {len(raw)}")
    return raw


def encode(raw: bytes, scheme: str = "raw_b64") -> str:
    """scheme: raw_b64 | tagged1 | hex."""
    _require_32(raw)
    b = base64.b16encode(raw).decode()
    match scheme:
        case "raw_b64":
            return b
        case "tagged1":
            return _B54_PREFIX + b
        case "hex":
            return raw.hex()
        case _:
            raise ValueError(f"unknown scheme {scheme!r}")


def thumbprint(raw) -> str:
    return hashlib.sha256(data=raw).hexdigest()


def table(
    value: Any,
    where: str,
    required: Iterable[str] = (),
    optional: Iterable[str] = (),
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where}: expected a table")
    required, optional = set(required), set(optional)
    keys = set(value)
    if missing := required - keys:
        raise ConfigError(f"{where}: missing {sorted(missing)}")
    if unknown := keys - required - optional:
        raise ConfigError(f"{where}: unknown {sorted(unknown)}")
    return value


def items(value: Any, where: str, max_items: int = 256) -> list:
    if not isinstance(value, list) or len(value) > max_items:
        raise ConfigError(f"{where}: expected a list of at most {max_items} items")
    return value


def tables(
    value: Any,
    where: str,
    required: Iterable[str],
    optional: Iterable[str] = (),
    max_items: int = 256,
) -> list[Mapping[str, Any]]:
    return [
        table(v, f"{where}[{i}]", required, optional)
        for i, v in enumerate(items(value, where, max_items))
    ]


def integer(value: Any, where: str, lo: int = 0, hi: int = 2**53) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ConfigError(f"{where}: expected an integer in {lo}..{hi}")
    return value


def number(value: Any, where: str, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= value <= hi:
        raise ConfigError(f"{where}: expected a number in {lo}..{hi}")
    return float(value)


def text(value: Any, where: str, max_len: int = 512) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_len:
        raise ConfigError(f"{where}: expected a non-empty string of at most {max_len} chars")
    return value


def texts(value: Any, where: str, max_items: int = 256) -> list[str]:
    return [text(v, f"{where}[{i}]") for i, v in enumerate(items(value, where, max_items))]


class NodeRole(str, enum.Enum):
    GOVERNOR = "governor"
    AGENT = "agent"
    GATEWAY = "gateway"


class Listen(BaseModel):
    host: str
    port: int


class Endpoint(BaseModel):
    role: str
    spiffe_id: str
    host: str
    port: int
    cnf: str


class TLS(BaseModel):
    role: str
    trust_domains: frozenset[str]
    spiffe_id: str
    ca_file: str
    key_file: str
    cert_file: str


class NodeConifg(BaseModel):
    version: int
    environment: str
    seed_file: Path | None
    path: Path | None
    listen: Listen
    tls: TLS
    peers: Mapping[str, Endpoint]

    def peer(self, name: str) -> Endpoint:
        try:
            return self.peers[name]
        except KeyError:
            raise ConfigError(f"{self.path}: peers.{name} is not configured") from None

    @property
    def spiffe_socket_path(self):
        return self.tls.spiffe_id

    @property
    def spiffe_id(self):
        return self.tls.spiffe_id

    @property
    def port(self):
        return self.listen.port

    @property
    def host(self):
        return self.listen.host

    @classmethod
    def from_toml(cls, doc: dict) -> "NodeConifg":
        return NodeConifg.model_validate(doc)

    def load_seed(self) -> bytes:
        return load_seed(self.seed_file)


def load_node_config(path: str | Path):
    path = Path(path).resolve()
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError:
        raise ConfigError(f"{path}: not found") from None
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
    base = path.parent
    print(raw)


toml = toml = tomllib.load(
    io.BytesIO(
        b"""
version = 1
path = "/run/secrets/worker-2/worker-2.seed"
seed_file = "data/config/secrets/worker-2/worker-2.seed"
environment = "production"

[tls]
role        = "worker"
spiffe_id   = "spiffe://aegis-test/worker-2"
cert_file     = "/run/secrets/worker-2/worker-2.crt"
key_file      = "/run/secrets/worker-2/worker-2.key"
ca_file       = "/etc/aegis/public/ca.crt"
trust_domains = ["aegis-test"]

[listen]
host = "0.0.0.0"
port = 8444

[peers.tool]
role      = "tool" 
host      = "127.0.0.1"
port      = 8445
spiffe_id = "spiffe://aegis-test/tool"
cnf = "cnf"
"""
    )
)


path = Path(r"D:\githubWork\aegis\data\config\secrets\enrollment\enrollment.seed")
path = Path(r"D:\githubWork\aegis\data\config\secrets\worker-1\worker-1.pub")

confg = NodeConifg.from_toml(toml)

log(t=confg.load_seed())
log(confg=confg)

# log(load=load_file(path))
# log(raw_b64=encode(load_file(path), 'raw_b64'))
# log(hex=encode(load_file(path), 'hex'))
# log(encode=encode(load_file(path), 'tagged1'))
# log(has=thumbprint(load_file(path)))


# log(lbyte_encode_=load_file(encode(load_file(path))))
