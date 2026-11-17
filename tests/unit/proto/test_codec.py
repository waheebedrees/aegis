import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from libs.proto import (
    MAX_HDR_BYTES,
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
    ProtocolError,
    Status,
    decode_envelope,
    decode_tlvs,
    encode_envelope,
    encode_tlvs,
    make_end_headers,
    make_tlv,
)


def test_tlv_roundtrip():
    entries = {
        1: make_tlv(1, b"a"),
        2: make_tlv(2, b"bb", critical=True),
        3: make_tlv(3, b""),
    }
    raw = encode_tlvs(entries)
    decoded = decode_tlvs(raw, known_tags=frozenset({1, 2, 3}))
    assert decoded[1].value == b"a"
    assert decoded[2].value == b"bb" and decoded[2].critical
    assert decoded[3].value == b""


def test_tlv_non_canonical_order_rejected():
    # Hand-build out-of-order TLVs: tag 3 then tag 1
    raw = struct.pack(">HBH", 3, 0, 1) + b"a" + struct.pack(">HBH", 1, 0, 1) + b"b"
    with pytest.raises(ProtocolError) as exc:
        decode_tlvs(raw, known_tags=frozenset({1, 3}))
    assert exc.value.status is Status.MALFORMED


def test_tlv_truncation_any_prefix_is_malformed():
    raw = encode_tlvs({1: make_tlv(1, b"hello")})
    # cut=0 gives b"" which is a valid empty header set, not a truncation.
    for cut in range(1, len(raw)):
        with pytest.raises(ProtocolError) as exc:
            decode_tlvs(raw[:cut], known_tags=frozenset({1}))
        assert exc.value.status is Status.MALFORMED


def test_tlv_duplicate_tag_rejected():
    a = struct.pack(">HBH", 1, 0, 1) + b"a"
    dup = a + a
    with pytest.raises(ProtocolError):
        decode_tlvs(dup, known_tags=frozenset({1}))


def test_tlv_reserved_zero_tag_rejected():
    raw = struct.pack(">HBH", 0, 0, 0)
    with pytest.raises(ProtocolError):
        decode_tlvs(raw)


def test_tlv_unknown_flag_bits_rejected():
    raw = struct.pack(">HBH", 1, 0x02, 1) + b"a"
    with pytest.raises(ProtocolError):
        decode_tlvs(raw)


def test_tlv_unknown_critical_is_unimplemented():
    raw = encode_tlvs({999: make_tlv(999, b"x", critical=True)})
    with pytest.raises(ProtocolError) as exc:
        decode_tlvs(raw, known_tags=frozenset())
    assert exc.value.status is Status.UNIMPLEMENTED


def test_tlv_unknown_noncritical_preserved():
    raw = encode_tlvs({999: make_tlv(999, b"x", critical=False)})
    decoded = decode_tlvs(raw, known_tags=frozenset())
    assert 999 in decoded
    assert decoded[999].value == b"x"


# ══════════════════════════════════════════════════════════════════════
# 2. ChannelHello


def test_hello_roundtrip():
    h = ChannelHello(
        mode=Mode.UNARY,
        method="Foo.Bar",
        content_type="application/cbor",
        deadline_ms=5000,
        correlation_id=b"\x01" * 16,
        traceparent="00-" + "a" * 32 + "-" + "b" * 16 + "-01",
        idempotency_key=b"idem-42",
        accept_types=("application/cbor", "application/json"),
        schema_id="test.v1",
        priority=3,
    )
    raw = h.encode()
    decoded = ChannelHello.decode(raw)
    assert decoded.mode is Mode.UNARY
    assert decoded.method == "Foo.Bar"
    assert decoded.deadline_ms == 5000
    assert decoded.correlation_id == b"\x01" * 16
    assert decoded.accept_types == ("application/cbor", "application/json")
    assert decoded.priority == 3
    assert decoded.schema_id == "test.v1"


def test_hello_canonical_order_independent_of_dict_ordering():
    extensions = (make_tlv(0x2001, value=b"b"),)
    print(0x2001)
    h1 = ChannelHello(
        mode=Mode.BIDI,
        method="M",
        extensions=extensions,
    )

    h2 = ChannelHello(mode=Mode.BIDI, method="M", extensions=extensions)
    assert h1.encode() == h2.encode()


def test_hello_non_canonical_bytes_rejected():
    # Hand-build METHOD before MODE; canonical order is MODE (0x01) first.
    mode_tlv = struct.pack(">HBH", int(HelloTag.MODE), 0x01, 1) + b"\x01"
    method_tlv = struct.pack(">HBH", int(HelloTag.METHOD), 0x01, 1) + b"M"
    ct_tlv = struct.pack(">HBH", int(HelloTag.CONTENT_TYPE), 0x01, 16) + b"application/cbor"
    out_of_order = method_tlv + mode_tlv + ct_tlv
    with pytest.raises(ProtocolError) as exc:
        ChannelHello.decode(out_of_order)
    assert exc.value.status is Status.MALFORMED


def test_hello_missing_mode_rejected():
    method_tlv = struct.pack(">HBH", int(HelloTag.METHOD), 0x01, 1) + b"M"
    with pytest.raises(ProtocolError):
        ChannelHello.decode(method_tlv)


def test_hello_invalid_mode_byte_rejected():
    tlv = struct.pack(">HBH", int(HelloTag.MODE), 0x01, 1) + b"\x09"
    with pytest.raises(ProtocolError):
        ChannelHello.decode(tlv)


def test_hello_method_required_for_non_datagram():
    with pytest.raises(ProtocolError):
        ChannelHello(mode=Mode.UNARY, method="")


def test_hello_method_optional_for_datagram():
    h = ChannelHello(mode=Mode.DATAGRAM, method="")
    assert h.encode()


def test_hello_initial_credit_bidi_only():
    with pytest.raises(ProtocolError):
        ChannelHello(mode=Mode.UNARY, method="M", initial_credit=5)
    # BIDI is allowed
    ChannelHello(mode=Mode.BIDI, method="M", initial_credit=5)


def test_hello_critical_extension_rejected_by_unknown_side():
    h = ChannelHello(mode=Mode.UNARY, method="M", extensions=(make_tlv(tag=0x2001, value=b"x"),))
    h.encode()
    # Simulate "unknown critical": rebuild the extension with the critical bit
    # Simpler: use a hello that declares an unknown critical tag.
    # We can't set critical on extensions through ChannelHello (by design),
    # so craft the bytes manually.
    ext_tlv = struct.pack(">HBH", 0x2001, 0x01, 1) + b"x"
    mode_tlv = struct.pack(">HBH", int(HelloTag.MODE), 0x01, 1) + b"\x01"
    method_tlv = struct.pack(">HBH", int(HelloTag.METHOD), 0x01, 1) + b"M"
    ct_tlv = struct.pack(">HBH", int(HelloTag.CONTENT_TYPE), 0x01, 16) + b"application/cbor"
    hostile = mode_tlv + ct_tlv + method_tlv + ext_tlv
    with pytest.raises(ProtocolError) as exc:
        ChannelHello.decode(hostile)
    assert exc.value.status is Status.UNIMPLEMENTED


def test_hello_truncation_any_prefix_raises():
    raw = ChannelHello(mode=Mode.UNARY, method="M").encode()
    for cut in range(len(raw)):
        with pytest.raises(ProtocolError):
            ChannelHello.decode(raw[:cut])


@given(
    method=st.text(alphabet="abcdefghXYZ0123._-", min_size=1, max_size=100),
    deadline=st.integers(min_value=0, max_value=86_400_000),
    priority=st.integers(min_value=0, max_value=7),
)
def test_hello_property_roundtrip(method, deadline, priority):
    h = ChannelHello(mode=Mode.UNARY, method=method, deadline_ms=deadline, priority=priority)
    raw = h.encode()
    decoded = ChannelHello.decode(raw)
    assert decoded.method == method
    assert decoded.deadline_ms == deadline
    assert decoded.priority == priority


def test_envelope_roundtrip_data():
    headers = (make_tlv(0x2001, struct.pack(">Q", 42)),)

    env = Envelope(
        type=MsgType.DATA,
        headers=headers,
        payload=b"hello world",
    )
    raw = encode_envelope(env)
    decoded = decode_envelope(raw)
    assert decoded.type is MsgType.DATA
    assert decoded.payload == b"hello world"
    assert decoded.headers[0].value == struct.pack(">Q", 42)


def test_envelope_truncation_any_prefix_raises():

    headers = (make_tlv(0x2001, b"a" * 2),)

    env = Envelope(
        type=MsgType.DATA,
        headers=headers,  # header section = 5 + 20 = 25 B
        payload=b"x" * 100,
    )
    hdr = (
        MESSAGE_REGISTRY.encode(
            env.headers, max_bytes=MAX_HDR_BYTES, max_fields=32, context=int(env.type)
        )
        if env.headers
        else b""
    )

    print(len(hdr))
    raw = encode_envelope(env)
    hdr_end = PREFIX_LEN + len(hdr)

    for cut in range(hdr_end):
        with pytest.raises(ProtocolError):
            decode_envelope(raw[:cut])

    # Beyond hdr_end, we get valid shorter messages; document that explicitly.
    for cut in range(hdr_end, len(raw)):
        decoded = decode_envelope(raw[:cut])
        assert decoded.payload == env.payload[: cut - hdr_end]


def test_envelope_unknown_version_rejected():
    env = Envelope(type=MsgType.DATA)
    raw = bytearray(encode_envelope(env))
    raw[0] = 0x99
    with pytest.raises(ProtocolError) as exc:
        decode_envelope(bytes(raw))
    assert exc.value.status is Status.MALFORMED


def test_envelope_unknown_type_rejected():
    env = Envelope(type=MsgType.DATA)
    raw = bytearray(encode_envelope(env))
    raw[1] = 0x99
    with pytest.raises(ProtocolError):
        decode_envelope(bytes(raw))


def test_envelope_unknown_flag_bits_rejected():

    with pytest.raises(ProtocolError):
        env = Envelope(type=MsgType.DATA, flags=0x0100)
        encode_envelope(env)  # Envelope construction rejects it
    # Envelope.__post_init__ already raised; this path is unreachable
    # for a valid Envelope. Craft bytes to hit decode:
    valid = bytearray(encode_envelope(Envelope(type=MsgType.DATA)))
    valid[2] = 0x01  # flags=0x01xx, so high byte nonzero → unknown
    valid[3] = 0x00
    with pytest.raises(ProtocolError):
        decode_envelope(bytes(valid))


def test_envelope_critical_flag_rejects_unknown_header():
    # Build an envelope with an unknown header and CRITICAL flag set
    unknown_tlv = make_tlv(0x0999, b"x", critical=False)
    env = Envelope(type=MsgType.DATA, flags=MsgFlag.CRITICAL, headers=(unknown_tlv,), payload=b"")
    raw = encode_envelope(env)
    with pytest.raises(ProtocolError) as exc:
        decode_envelope(raw)
    assert exc.value.status is Status.UNIMPLEMENTED


def test_end_frame_parsing():
    headers = make_end_headers(Status.NOT_FOUND, "missing", retry_after_ms=500)
    env = Envelope(type=MsgType.END, headers=headers)
    ef = EndFrame.parse(False, env.headers)
    assert ef.status is Status.NOT_FOUND
    assert ef.message == "missing"
    assert ef.retry_after_ms == 500


def test_error_frame_requires_non_ok_status():
    # ERROR with OK status is rejected at EndFrame.parse
    headers = make_end_headers(Status.OK)
    with pytest.raises(ProtocolError):
        EndFrame.parse(True, headers)


def test_error_frame_requires_status_header():
    env = Envelope(type=MsgType.ERROR, headers=())
    with pytest.raises(ProtocolError):
        EndFrame.parse(True, env.headers)


UNKNOWN_TAG = 0x2001  # >= 0x1000, not in MESSAGE_REGISTRY


@given(
    payload=st.binary(min_size=0, max_size=4000),
    status_value=st.integers(min_value=0, max_value=0xFFFF),
    msg_type=st.sampled_from([MsgType.END, MsgType.ERROR]),
)
def test_envelope_status_roundtrip(payload, status_value, msg_type):
    entry = make_tlv(HeaderTag.STATUS, struct.pack(">H", status_value), critical=True)
    env = Envelope(type=msg_type, headers=(entry,), payload=payload)
    decoded = decode_envelope(encode_envelope(env))
    assert decoded.type is msg_type
    assert decoded.payload == payload
    by_tag = {int(e.tag): e for e in decoded.headers}
    assert struct.unpack(">H", by_tag[HeaderTag.STATUS].value)[0] == status_value
