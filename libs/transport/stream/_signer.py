from __future__ import annotations
import hmac
import struct
import hashlib

from typing import runtime_checkable, Protocol

from libs.transport.stream.errors import stream_error, Status

_CHUNK_DOMAIN = b"aegis/stream-chunk/v4"
_CHUNK_HDR = struct.Struct(">IQBI")


@runtime_checkable
class StreamSigner(Protocol):
    """Authenticates outbound chunks and verifies inbound ones.

    Implementations MUST bind at least (direction, stream_id, seq, fin, data).
    sign() must be a pure function of its arguments: the transport calls it
    exactly once per (stream_id, seq) and never retries.
    """

    def sign(self, stream_id: int, seq: int, fin: bool, data: bytes) -> bytes: ...

    def verify(self, stream_id: int, seq: int, fin: bool, data: bytes, mac: bytes) -> None: ...


class HmacStreamSigner:
    """Default signer. Direction-separated HMAC-SHA256 over an unambiguous,
    length-prefixed encoding of (stream_id, seq, fin, len(data), data).

    The send and receive keys are distinct halves of the TLS exporter split,
    so a peer cannot reflect our own chunks back at us, and a chunk is bound
    to its stream id, so it cannot be replayed onto another stream.
    """

    __slots__ = ("_send_key", "_recv_key")

    def __init__(self, send_ikm: bytes, recv_ikm: bytes) -> None:
        for k in (send_ikm, recv_ikm):
            if not isinstance(k, (bytes, bytearray)) or len(k) < 32:
                raise ValueError("stream keys must be at least 32 bytes")
        if hmac.compare_digest(bytes(send_ikm), bytes(recv_ikm)):
            raise ValueError("send and receive keys must differ")
        self._send_key = bytes(send_ikm)
        self._recv_key = bytes(recv_ikm)

    @staticmethod
    def _mac(key: bytes, stream_id: int, seq: int, fin: bool, data: bytes) -> bytes:
        h = hmac.new(key, None, hashlib.sha256)
        h.update(_CHUNK_DOMAIN)
        h.update(_CHUNK_HDR.pack(stream_id, seq, 1 if fin else 0, len(data)))
        h.update(data)
        return h.digest()

    def sign(self, stream_id: int, seq: int, fin: bool, data: bytes) -> bytes:
        return self._mac(self._send_key, stream_id, seq, fin, data)

    def verify(self, stream_id: int, seq: int, fin: bool, data: bytes, mac: bytes) -> None:
        expected = self._mac(self._recv_key, stream_id, seq, fin, data)
        if not hmac.compare_digest(expected, mac):
            raise stream_error(Status.UNAUTHENTICATED, "MAC_MISMATCH", str(stream_id))
