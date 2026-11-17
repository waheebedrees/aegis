"""tests/unit/proto/test_fragment.py — Fragmenter invariants (spec §3.2)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from libs.proto.envelope import (
    MAX_ENVELOPE_BYTES,
    PREFIX_LEN,
    Envelope,
    MsgFlag,
    MsgType,
    decode_envelope,
    encode_envelope,
)
from libs.proto.fragment import Fragmenter, Reassembler
from libs.proto.status import ProtocolError, Status
from libs.proto.tlv import make_tlv

MIN_CHUNK = PREFIX_LEN + 64  # = 70, the Fragmenter floor


# --------------------------------------------------------------------------
# Constructor bounds
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        0,
        MIN_CHUNK - 1,
        MAX_ENVELOPE_BYTES + 1,
        1 << 20,
    ],
)
def test_ctor_rejects_out_of_bounds(bad):
    with pytest.raises(ValueError):
        Fragmenter(max_chunk_bytes=bad)


@pytest.mark.parametrize("ok", [MIN_CHUNK, MAX_ENVELOPE_BYTES])
def test_ctor_accepts_boundary(ok):
    Fragmenter(max_chunk_bytes=ok)  # must not raise


# --------------------------------------------------------------------------
# Single-fragment path (no FRAG_MORE)
# --------------------------------------------------------------------------


def test_empty_data_yields_one_empty_envelope():
    frags = list(Fragmenter(512).fragment(b""))
    assert len(frags) == 1
    (only,) = frags
    assert only.type is MsgType.DATA
    assert only.payload == b""
    assert only.headers == ()
    assert only.flags == MsgFlag.NONE


def test_small_data_yields_one_envelope():
    frags = list(Fragmenter(512).fragment(b"hello"))
    assert len(frags) == 1
    (only,) = frags
    assert only.payload == b"hello"
    assert only.flags == MsgFlag.NONE


def test_data_exactly_at_first_cap_is_single():
    # max_chunk=512, one header: hdr_bytes = 5 (TLV hdr) + 3 (b"tag") = 8
    # first_overhead = 6 + 8 = 14  →  first_cap = 512 - 14 = 498
    hdrs = (make_tlv(0x1000, b"tag"),)
    data = b"x" * 498
    frags = list(Fragmenter(512).fragment(data, headers=hdrs))
    assert len(frags) == 1
    assert frags[0].payload == data
    assert frags[0].flags == MsgFlag.NONE
    assert frags[0].headers == hdrs


def test_one_byte_past_first_cap_splits():
    hdrs = (make_tlv(0x1000, b"tag"),)  # first_cap = 498
    data = b"x" * 499
    frags = list(Fragmenter(512).fragment(data, headers=hdrs))
    assert len(frags) == 2
    assert frags[0].payload == data[:498]
    assert frags[1].payload == data[498:]
    assert frags[0].flags & MsgFlag.FRAG_MORE
    assert not (frags[1].flags & MsgFlag.FRAG_MORE)


# --------------------------------------------------------------------------
# Multi-fragment path
# --------------------------------------------------------------------------


def test_headers_only_on_first_fragment():
    hdrs = (make_tlv(0x1000, b"tag"),)
    frags = list(Fragmenter(512).fragment(b"y" * 2000, headers=hdrs))
    assert len(frags) >= 2
    assert frags[0].headers == hdrs
    for f in frags[1:]:
        assert f.headers == ()


def test_all_but_last_carry_frag_more():
    frags = list(Fragmenter(512).fragment(b"z" * 5000))
    assert len(frags) >= 2
    for f in frags[:-1]:
        assert f.flags & MsgFlag.FRAG_MORE
    assert not (frags[-1].flags & MsgFlag.FRAG_MORE)


def test_payload_concatenation_is_lossless():
    data = bytes(range(256)) * 50  # 12 800 bytes
    frags = list(Fragmenter(512).fragment(data))
    assert b"".join(f.payload for f in frags) == data


def test_all_fragments_are_data_type():
    frags = list(Fragmenter(512).fragment(b"q" * 1000))
    assert all(f.type is MsgType.DATA for f in frags)


# --------------------------------------------------------------------------
# Chunk budget honoured on the wire
# --------------------------------------------------------------------------


@pytest.mark.parametrize("chunk", [MIN_CHUNK, 128, 512, 4096])
def test_encoded_fragment_fits_chunk_budget(chunk):
    hdrs = (make_tlv(0x1000, b"h" * 8),)
    data = b"d" * (chunk * 10)
    for f in Fragmenter(chunk).fragment(data, headers=hdrs):
        assert len(encode_envelope(f)) <= chunk


def test_headers_too_large_for_chunk_raises():
    # MIN_CHUNK = 70.  first_overhead = 6 + len(hdr_bytes) must be < 70.
    # A single TLV of value length 64 gives hdr_bytes = 5 + 64 = 69,
    # so first_overhead = 6 + 69 = 75 ≥ 70 → must fail.
    hdrs = (make_tlv(0x1000, b"v" * 64),)
    with pytest.raises(ProtocolError) as exc:
        list(Fragmenter(MIN_CHUNK).fragment(b"data", headers=hdrs))
    assert exc.value.status is Status.INVALID_ARGUMENT


def test_non_bytes_data_rejected():
    with pytest.raises(ProtocolError) as exc:
        list(Fragmenter(512).fragment("not bytes"))  # type: ignore[arg-type]
    assert exc.value.status is Status.INVALID_ARGUMENT


# --------------------------------------------------------------------------
# Round-trips
# --------------------------------------------------------------------------


def test_fragments_reassemble_losslessly():
    data = b"payload-" * 500
    frags = list(Fragmenter(512).fragment(data, headers=(make_tlv(0x1000, b"tag"),)))
    r = Reassembler()
    result = None
    for f in frags:
        result = r.feed(f)
        if result is not None:
            break
    assert result is not None
    assert result.data == data
    assert result.headers == (make_tlv(0x1000, b"tag"),)
    assert not r.in_progress


def test_fragments_survive_wire_codec_roundtrip():
    """The full encode → decode → reassemble path (what a real transport does)."""
    data = bytes(range(256)) * 20
    hdrs = (make_tlv(0x1000, b"tag"),)
    frags = list(Fragmenter(512).fragment(data, headers=hdrs))

    r = Reassembler()
    result = None
    for f in frags:
        decoded = decode_envelope(encode_envelope(f))
        result = r.feed(decoded)
        if result is not None:
            break

    assert result is not None
    assert result.data == data
    assert result.headers == hdrs
    assert not r.in_progress


# --------------------------------------------------------------------------
# Property-based
# --------------------------------------------------------------------------


@given(
    data=st.binary(min_size=0, max_size=2000),
    chunk=st.integers(min_value=MIN_CHUNK, max_value=512),
)
@settings(max_examples=200)
def test_property_fragment_reassembles(data, chunk):
    frags = list(Fragmenter(chunk).fragment(data))
    r = Reassembler(max_message_bytes=1 << 20, max_fragments=1 << 16)

    result = None
    for f in frags:
        result = r.feed(f)
        if result is not None:
            break

    assert result is not None
    assert result.data == data
    assert not r.in_progress


@given(
    data=st.binary(min_size=1, max_size=2000),
    tag=st.integers(min_value=0x1000, max_value=0xFFFF),
    value=st.binary(min_size=1, max_size=32),
    chunk=st.integers(min_value=MIN_CHUNK, max_value=512),
)
@settings(max_examples=200)
def test_property_headers_preserved(data, tag, value, chunk):
    hdrs = (make_tlv(tag, value),)
    try:
        frags = list(Fragmenter(chunk).fragment(data, headers=hdrs))
    except ProtocolError:
        # Header does not fit into the caller-chosen chunk budget: this is a
        # legal rejection, not a bug.
        return

    r = Reassembler(max_message_bytes=1 << 20, max_fragments=1 << 16)
    result = None
    for f in frags:
        result = r.feed(f)
        if result is not None:
            break

    assert result is not None
    assert result.data == data
    assert result.headers == hdrs


@given(
    data=st.binary(min_size=1, max_size=2000),
    chunk=st.integers(min_value=MIN_CHUNK, max_value=512),
)
@settings(max_examples=100)
def test_property_every_encoded_fragment_fits_budget(data, chunk):
    for f in Fragmenter(chunk).fragment(data):
        assert PREFIX_LEN + len(f.payload) <= chunk  # no headers
        assert len(encode_envelope(f)) <= chunk


def test_fragment_single_piece():
    frags = list(Fragmenter(max_chunk_bytes=1024).fragment(b"hi"))
    assert len(frags) == 1
    assert not frags[0].is_frag_more
    assert frags[0].payload == b"hi"


def test_fragment_multiple_pieces():
    data = b"x" * 10_000
    frags = list(Fragmenter(max_chunk_bytes=1024).fragment(data))
    assert len(frags) > 1
    for f in frags[:-1]:
        assert f.is_frag_more
    assert not frags[-1].is_frag_more
    assert b"".join(f.payload for f in frags) == data


def test_reassembler_bomb_empty_frag_more():
    r = Reassembler()
    with pytest.raises(ProtocolError):
        r.feed(Envelope(type=MsgType.DATA, flags=MsgFlag.FRAG_MORE, payload=b""))


def test_reassembler_bomb_too_many_fragments():
    r = Reassembler(max_fragments=3)
    for _ in range(3):
        r.feed(Envelope(type=MsgType.DATA, flags=MsgFlag.FRAG_MORE, payload=b"x"))
    with pytest.raises(ProtocolError) as exc:
        r.feed(Envelope(type=MsgType.DATA, flags=MsgFlag.FRAG_MORE, payload=b"x"))
    assert exc.value.status is Status.RESOURCE_EXHAUSTED


def test_reassembler_bomb_too_large():
    r = Reassembler(max_message_bytes=10, max_fragments=100)
    r.feed(Envelope(type=MsgType.DATA, flags=MsgFlag.FRAG_MORE, payload=b"123456"))  # 6
    with pytest.raises(ProtocolError) as exc:
        r.feed(Envelope(type=MsgType.DATA, payload=b"78901"))  # 5 → 11 > 10
    assert exc.value.status is Status.RESOURCE_EXHAUSTED


def test_reassembler_continuation_with_headers_rejected():
    r = Reassembler()
    r.feed(Envelope(type=MsgType.DATA, flags=MsgFlag.FRAG_MORE, payload=b"p1"))
    with pytest.raises(ProtocolError):
        r.feed(Envelope(type=MsgType.DATA, headers=(make_tlv(1, b"x"),), payload=b"p2"))


def test_reassembler_interrupted_by_non_data():
    r = Reassembler()
    r.feed(Envelope(type=MsgType.DATA, flags=MsgFlag.FRAG_MORE, payload=b"p1"))
    with pytest.raises(ProtocolError):
        r.check_no_partial("END")


def test_reassembler_poisoned_after_error():
    r = Reassembler()
    with pytest.raises(ProtocolError):
        r.feed(Envelope(type=MsgType.DATA, flags=MsgFlag.FRAG_MORE, payload=b""))
    with pytest.raises(ProtocolError):
        r.feed(Envelope(type=MsgType.DATA, payload=b"x"))


@given(
    data=st.binary(min_size=0, max_size=8000),
    chunk=st.integers(min_value=128, max_value=1024),
)
@settings(max_examples=30, deadline=None)
def test_property_fragment_reassemble(data, chunk):
    frags = list(Fragmenter(max_chunk_bytes=chunk).fragment(data))
    r = Reassembler()
    result = None
    for f in frags:
        result = r.feed(f)
    assert result is not None
    assert result.data == data
