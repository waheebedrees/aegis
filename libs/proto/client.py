"""libs/proto/client.py — client runtime over one Transport.

Connection pooling, redial, and retries belong to M5; this layer maps one
logical call onto one channel and nothing more.
"""

import secrets
from dataclasses import dataclass
from typing import Any, Iterable, Optional


from libs.proto.headers import HeaderRegistry
from libs.proto.status import error, ChannelError, Status
from libs.proto.hello import Mode
from libs.proto.codec import JSON, Codec, CodecRegistry
from libs.proto.channel import ChannelConfig, ChannelHello, Channel
from libs.proto.tlv import TLVEntry
from libs.transport.stream_session import Transport

__all__ = ["ClientConfig"]


MAX_DEADLINE_MS = 24 * 60 * 60 * 1000


@dataclass(frozen=True, slots=True)
class ClientConfig:
    channel: ChannelConfig = ChannelConfig()
    content_type: str = JSON
    deadline_ms: int = 30_000  # 0 = none; strongly discouraged

    def __post_init__(self) -> None:
        if not isinstance(self.channel, ChannelConfig):
            raise TypeError("channel must be a ChannelConfig")
        if type(self.deadline_ms) is not int or not 0 <= self.deadline_ms <= MAX_DEADLINE_MS:
            raise ValueError("deadline_ms out of range")
