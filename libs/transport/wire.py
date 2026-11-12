""" stateless wire rules, hello codec, and validators.

No classes holding connection or stream state live here. ClientConnector and
ServerConnector (or, in the unsplit tree, the single Transport) call these pure
functions so their wire behavior stays byte-identical without sharing a base
class.

Wire v5: STREAM_DATA carries an empty pop. Frame integrity comes from TLS 1.3
AEAD plus the frame parser's own structural checks. There is no chunk MAC.
"""

from __future__ import annotations


import math
import struct
from dataclasses import dataclass

from libs.transport.frame import (
    FIXED_OVERHEAD,
    MAX_CHUNK_BYTES,
    MAX_FRAME_BYTES,
    MAX_STREAM_ID,
    MAX_WINDOW_CREDIT,
    OPEN_MAX_BODY,
    OPEN_MAX_POP,
    OPEN_MAX_TOKEN,
    Frame,
    Flags,
    FrameError,
    FrameType,
    StreamChunk,
    make_session_init,
    parse_stream_data,
)

__all__ = [
    "PROTOCOL_VERSION",
    "FEATURES",
    "BUFFERED_TUPLE_COST",
    "MAX_PENDING_HARD_CAP",
    "MAX_CONNECTIONS",
    "MAX_PER_PEER",
    "MAX_HANDSHAKE_CONCURRENCY",
    "MIN_MAX_FRAME",
    "MIN_STREAM_WINDOW",
    "MAX_STREAM_WINDOW",
    "MAX_STREAMS",
    "MAX_BUFFERED",
    "PER_STREAM_OVERHEAD",
    "MAX_STREAM_OVERHEAD",
    "HANDSHAKE_MAX_PAYLOAD",
    "CLOSE_WRITE_TIMEOUT",
    "SHUTDOWN_GRACE",
    "MAX_OUTSTANDING_PINGS",
    "MAX_STALE_BYTES",
    "RETIRED_RING_FACTOR",
    "TransportConfig",
    "PeerLimits",
    "TransportError",
    "StreamError",
    "safe_ascii",
    "peer_addr",
    "encode_hello",
    "parse_hello",
    "build_data_frame",
    "parse_data",
    "check_client_sid",
    "check_data",
    "check_credit",
    "max_send_chunk",
]

PROTOCOL_VERSION = 5
FEATURE_STREAMS = 0x0001
FEATURES = FEATURE_STREAMS            # exact match; unknown features rejected

MIN_MAX_FRAME = 64 * 1024
MIN_STREAM_WINDOW = 4 * 1024
MAX_STREAM_WINDOW = 1024 * 1024
MAX_STREAMS = 256
MAX_BUFFERED = 32 * 1024 * 1024
PER_STREAM_OVERHEAD = OPEN_MAX_TOKEN + OPEN_MAX_POP + OPEN_MAX_BODY
MAX_STREAM_OVERHEAD = 4 * 1024 * 1024

HANDSHAKE_MAX_PAYLOAD = FIXED_OVERHEAD + 64
CLOSE_WRITE_TIMEOUT = 1.0
SHUTDOWN_GRACE = 0.5
MAX_OUTSTANDING_PINGS = 3
MAX_STALE_BYTES = 8 * 1024 * 1024
RETIRED_RING_FACTOR = 8

MAX_CONNECTIONS = 256
MAX_PER_PEER = 16
MAX_HANDSHAKE_CONCURRENCY = 64
BUFFERED_TUPLE_COST = 200
MAX_PENDING_HARD_CAP = 1024

# version, features, max_frame, stream_window, max_streams
_HELLO = struct.Struct(">HIIIH")
_U64 = struct.Struct(">Q")


class TransportError(Exception):
    """Connection-fatal error. `notify` controls whether CLOSE is sent."""

    __slots__ = ("code", "detail", "notify")

    def __init__(self, code: str, detail: str = "", *, notify: bool = True) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.notify = notify


class StreamError(Exception):
    """Stream-scoped error or local misuse. Connection stays up."""

    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def safe_ascii(text: object, limit: int = 128) -> str:
    return "".join(c if " " <= c <= "~" else "_" for c in str(text)[:limit])


def peer_addr(writer: object) -> str:
    try:
        peer = writer.get_extra_info("peername")  # type: ignore[attr-defined]
    except Exception:
        return "-"
    if isinstance(peer, tuple) and len(peer) >= 2:
        return f"{safe_ascii(peer[0], 64)}:{safe_ascii(peer[1], 8)}"
    return "-"


def _pos(value: object, name: str) -> None:
    if type(value) not in (int, float) or not math.isfinite(float(value)) or value <= 0: # type: ignore
        raise ValueError(f"{name} must be a finite positive number")


def _bounded(value: object, name: str, lo: int, hi: int) -> None:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{name} must be an int in {lo}..{hi}")


@dataclass(frozen=True, slots=True)
class TransportConfig:
    max_frame: int = MAX_FRAME_BYTES
    max_streams: int = 32
    stream_window: int = 256 * 1024
    handshake_timeout: float = 10.0
    write_timeout: float = 30.0
    idle_timeout: float = 60.0
    frame_timeout: float = 30.0
    ping_interval: float = 20.0
    stream_idle_timeout: float = 300.0
    cert_grace_s: float = 15.0
    allow_tls_only:bool= True

    def __post_init__(self) -> None:
        _bounded(self.max_frame, "max_frame", MIN_MAX_FRAME, MAX_FRAME_BYTES)
        _bounded(self.max_streams, "max_streams", 1, MAX_STREAMS)
        _bounded(self.stream_window, "stream_window",
                 MIN_STREAM_WINDOW, MAX_STREAM_WINDOW)
        if self.max_streams * self.stream_window > MAX_BUFFERED:
            raise ValueError("max_streams * stream_window exceeds MAX_BUFFERED")
        if self.max_streams * PER_STREAM_OVERHEAD > MAX_STREAM_OVERHEAD:
            raise ValueError(
                "max_streams * per-stream OPEN metadata exceeds MAX_STREAM_OVERHEAD"
            )
        if FIXED_OVERHEAD + 8 + min(self.stream_window, MAX_CHUNK_BYTES) > self.max_frame:
            raise ValueError("max_frame too small for stream_window")
        for name in (
            "handshake_timeout", "write_timeout", "idle_timeout",
            "frame_timeout", "ping_interval", "stream_idle_timeout", "cert_grace_s",
        ):
            _pos(getattr(self, name), name)
        if self.idle_timeout < 2 * self.ping_interval:
            raise ValueError("idle_timeout must be >= 2 * ping_interval")
        if self.frame_timeout > self.idle_timeout:
            raise ValueError("frame_timeout must be <= idle_timeout")


@dataclass(frozen=True, slots=True)
class PeerLimits:
    max_frame: int
    stream_window: int
    max_streams: int
    features: int


# ───────────────────────── stateless wire functions ─────────────────────────

def encode_hello(cfg: TransportConfig) -> Frame:
    body = _HELLO.pack(
        PROTOCOL_VERSION,
        FEATURES,
        cfg.max_frame,
        cfg.stream_window,
        cfg.max_streams,
    )
    return make_session_init(body)


def parse_hello(f: Frame) -> PeerLimits:
    if f.type != FrameType.SESSION_INIT:
        raise TransportError("EXPECTED_HELLO", FrameType.name(f.type))
    if f.stream_id or f.flags or f.token or f.pop:
        raise TransportError("BAD_HELLO", "non-empty header fields")
    if len(f.body) != _HELLO.size:
        raise TransportError("BAD_HELLO", f"length {len(f.body)}")

    version, features, max_frame, stream_window, max_streams = _HELLO.unpack(f.body)
    if version != PROTOCOL_VERSION:
        raise TransportError("VERSION", str(version))
    if features != FEATURES:
        raise TransportError("FEATURES", f"0x{features:x}")
    if not MIN_MAX_FRAME <= max_frame <= MAX_FRAME_BYTES:
        raise TransportError("MAX_FRAME", str(max_frame))
    if not MIN_STREAM_WINDOW <= stream_window <= MAX_STREAM_WINDOW:
        raise TransportError("STREAM_WINDOW", str(stream_window))
    if not 1 <= max_streams <= MAX_STREAMS:
        raise TransportError("MAX_STREAMS", str(max_streams))

    return PeerLimits(
        max_frame=max_frame,
        stream_window=stream_window,
        max_streams=max_streams,
        features=features,
    )


def build_data_frame(sid: int, seq: int, data: bytes, fin: bool) -> Frame:
    """Build an outbound STREAM_DATA frame. No pop in wire v5."""
    if not data and not fin:
        raise StreamError("EMPTY_CHUNK")
    return Frame(
        type=FrameType.STREAM_DATA,
        stream_id=sid,
        flags=Flags.FIN if fin else Flags.NONE,
        body=_U64.pack(seq) + data,
    )


def parse_data(frame: Frame) -> StreamChunk:
    """Parse an inbound STREAM_DATA frame against the v5 default registry."""
    return parse_stream_data(frame)


def check_client_sid(sid: int, last_peer_sid: int) -> None:
    if not 1 <= sid <= MAX_STREAM_ID or sid % 2 == 0:
        raise TransportError("BAD_STREAM_ID", f"{sid} is not odd client stream id")
    if sid <= last_peer_sid:
        raise TransportError("BAD_STREAM_ID", f"{sid} <= {last_peer_sid}")


def check_data(
    *,
    seq_expected: int,
    buffered: int,
    window: int,
    remote_fin: bool,
    chunk: StreamChunk,
) -> None:
    if remote_fin:
        raise TransportError("DATA_AFTER_FIN", str(chunk.stream_id))
    if chunk.seq != seq_expected:
        raise TransportError("SEQ", f"{chunk.seq} != {seq_expected}")
    if buffered + len(chunk.data) + BUFFERED_TUPLE_COST > window:
        raise TransportError("FLOW_CONTROL", str(chunk.stream_id))


def check_credit(*, granted: int, sent: int, credits: int, sid: int) -> None:
    if not 1 <= credits <= MAX_WINDOW_CREDIT:
        raise TransportError("BAD_CREDITS", str(credits))
    if granted + credits > sent:
        raise TransportError("CREDIT_OVERRUN", str(sid))


def max_send_chunk(peer_window: int, peer_max_frame: int) -> int:
    return max(0, min(MAX_CHUNK_BYTES, peer_window,
                      peer_max_frame - (FIXED_OVERHEAD + 8)))