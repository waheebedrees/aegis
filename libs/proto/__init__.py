"""M1 — channel core (spec §2§3).

Public API:
    from libs.proto import Channel, ChannelHello, Mode, Status, ProtocolError
"""

from libs.proto.channel import (
    ByteStream,
    Channel,
    ChannelConfig,
    accept_channel,
    open_channel,
)
from libs.proto.codec import DEFAULT_CODECS, Codec, JsonCodec, RawCodec
from libs.proto.envelope import (
    HELLO_REGISTRY,
    MAX_ENVELOPE_BYTES,
    MAX_HDR_BYTES,
    MAX_HELLO_BYTES,
    MESSAGE_REGISTRY,
    PREFIX_LEN,
    ChannelHello,
    EndFrame,
    Envelope,
    HeaderTag,
    HelloTag,
    Mode,
    MsgFlag,
    MsgType,
    decode_envelope,
    encode_envelope,
    make_end_headers,
)
from libs.proto.fragment import (
    DEFAULT_MAX_FRAGMENTS,
    DEFAULT_MAX_MESSAGE_BYTES,
    Fragmenter,
    Message,
    Reassembler,
)
from libs.proto.status import (
    IDEMPOTENT_ONLY_RETRY,
    RETRYABLE,
    ChannelError,
    ProtocolError,
    RemoteError,
    Status,
    malformed,
    map_stream_error,
)
from libs.proto.tlv import (
    TLV_CRITICAL,
    HeaderRegistry,
    HeaderSpec,
    TLVEntry,
    decode_tlvs,
    encode_tlvs,
    make_tlv,
)

__all__ = [
    # status
    "Status",
    "RETRYABLE",
    "IDEMPOTENT_ONLY_RETRY",
    "DEFAULT_CODECS",
    "ChannelError",
    "ProtocolError",
    "RemoteError",
    "malformed",
    "map_stream_error",
    # tlv
    "TLVEntry",
    "TLV_CRITICAL",
    "HeaderSpec",
    "HeaderRegistry",
    "make_tlv",
    "encode_tlvs",
    "decode_tlvs",
    # codec
    "Codec",
    "JsonCodec",
    "RawCodec",
    # hello
    "Mode",
    "HelloTag",
    "ChannelHello",
    "HELLO_REGISTRY",
    "MAX_HELLO_BYTES",
    # envelope
    "MsgType",
    "MsgFlag",
    "HeaderTag",
    "MESSAGE_REGISTRY",
    "Envelope",
    "encode_envelope",
    "decode_envelope",
    "EndFrame",
    "make_end_headers",
    "PREFIX_LEN",
    "MAX_ENVELOPE_BYTES",
    "MAX_HDR_BYTES",
    # fragment
    "Fragmenter",
    "Reassembler",
    "Message",
    "DEFAULT_MAX_MESSAGE_BYTES",
    "DEFAULT_MAX_FRAGMENTS",
    # channel
    "Channel",
    "ChannelConfig",
    "ByteStream",
    "open_channel",
    "accept_channel",
]
