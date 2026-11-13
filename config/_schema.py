"""
strict readers shared by node and governance config.

Every reader rejects unknown keys, wrong types, and out-of-range values.
A typo in a config file is an error, never a silently ignored setting.

Wildcard conventions (three different ones, deliberately):

  SPIFFE identities:  only ``prefix/*`` at the very end, exactly one
                      path segment. ``spiffe://aegis/agents/*`` matches
                      ``spiffe://aegis/agents/planner`` but NOT
                      ``spiffe://aegis/agents/planner/sub``.
                      Enforced by ``spiffe(..., pattern=True)``.

  Tool identifiers:   ``"*"`` as the SOLE member of a list means
                      "any tool". Must not be combined with other
                      members. Enforced by ``capchain.Scope``.

  Pricing tool keys:  ``"namespace:*"`` matches every action under
                      the namespace (``"search:*"`` matches
                      ``search:query``, ``search:suggest``). Exact
                      keys match exactly. No other wildcard shape
                      is recognized.

  There is no ``search:*`` in ``scope.tools``. If you want to scope
  by namespace, list the specific tools, or use ``"*"`` and rely on
  pricing's ``default`` rule plus a policy edge ceiling to bound the
  budget.
"""

from __future__ import annotations
import datetime as dt
from pathlib import Path
from typing import Any, Iterable, Mapping

__all__ = [
    "ConfigError", "table", "tables", "items", "integer", "number",
    "text", "texts", "spiffe", "epoch", "file_path",
]


class ConfigError(Exception):
    """Invalid configuration.

    At startup: refuse to start.
    On reload:  keep the previous version and log.
    """


def table(value: Any, where: str, required: Iterable[str] = (),
          optional: Iterable[str] = ()) -> Mapping[str, Any]:
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


def tables(value: Any, where: str, required: Iterable[str],
           optional: Iterable[str] = (), max_items: int = 256
           ) -> list[Mapping[str, Any]]:
    return [table(v, f"{where}[{i}]", required, optional)
            for i, v in enumerate(items(value, where, max_items))]


def integer(value: Any, where: str, lo: int = 0, hi: int = 2**53) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ConfigError(f"{where}: expected an integer in {lo}..{hi}")
    return value


def number(value: Any, where: str, lo: float, hi: float) -> float:
    if (isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not lo <= value <= hi):
        raise ConfigError(f"{where}: expected a number in {lo}..{hi}")
    return float(value)


def text(value: Any, where: str, max_len: int = 512) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_len:
        raise ConfigError(
            f"{where}: expected a non-empty string of at most {max_len} chars")
    return value


def texts(value: Any, where: str, max_items: int = 256) -> list[str]:
    return [text(v, f"{where}[{i}]")
            for i, v in enumerate(items(value, where, max_items))]


def spiffe(value: Any, where: str, *, pattern: bool = False) -> str:
    s = text(value, where)
    if not s.startswith("spiffe://") or len(s) <= len("spiffe://"):
        raise ConfigError(f"{where}: expected a spiffe:// identity")
    if any(c.isspace() for c in s) or "/../" in s or "/./" in s \
            or s.endswith(("/..", "/.")):
        raise ConfigError(f"{where}: illegal path segment")
    stars = s.count("*")
    if stars and not (pattern and stars == 1 and s.endswith("/*")):
        raise ConfigError(
            f"{where}: wildcard only allowed as a trailing '/*' in patterns")
    return s



def epoch(value: Any, where: str) -> int:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            raise ConfigError(
                f"{where}: datetime must include a UTC offset (e.g. ...Z)")
        return int(value.timestamp())

    if isinstance(value, str):
        s = value.strip()
        try:
            parsed = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            raise ConfigError(
                f"{where}: expected ISO-8601 datetime "
                f"(e.g. 2026-11-01T00:00:00Z), got {value!r}") from None
        if parsed.tzinfo is None:
            raise ConfigError(
                f"{where}: datetime must include a UTC offset (e.g. ...Z)")
        return int(parsed.timestamp())

    return integer(value, where)


def file_path(value: Any, where: str, base: Path, *,
              must_exist: bool = True) -> Path:
    path = Path(text(value, where, 4096))
    if not path.is_absolute():
        path = base / path
    path = path.resolve()
    if must_exist and not path.is_file():
        raise ConfigError(f"{where}: file not found: {path}")
    return path






