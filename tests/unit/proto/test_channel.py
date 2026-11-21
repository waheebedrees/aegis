"""tests/unit/proto/test_channel.py — Channel invariants (spec §2.1, §3.4)."""

import asyncio
import time

import pytest

from libs.proto import (
    Channel,
    ChannelConfig,
    RawCodec,
    accept_channel,
    open_channel,
)
from libs.proto.channel import EOF
from libs.proto.hello import ChannelHello, Mode
from libs.proto.envelope import MsgType
from libs.proto.fragment import DEFAULT_MAX_FRAGMENTS
from libs.proto.status import ProtocolError, RemoteError, Status


class FakeByteStream:
    """In-memory duplex byte stream. Pair two with attach() and they talk."""

    def __init__(self, peer_id: str = "peer", kind: str = "test") -> None:
        self._peer_id = peer_id
        self._kind = kind
        self._open_payload = b""
        self._incoming: asyncio.Queue = asyncio.Queue()
        self._other: FakeByteStream | None = None
        self._cancelled = False
        self._sent_fin = False
        self.sent: list[tuple[bytes, bool]] = []
        self.cancel_reason: str | None = None

    def attach(self, other: "FakeByteStream") -> None:
        self._other = other
        other._other = self

    @property
    def peer_id(self) -> str:
        return self._peer_id

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def open_payload(self) -> bytes:
        return self._open_payload

    @open_payload.setter
    def open_payload(self, value: bytes) -> None:
        self._open_payload = value

    async def send(self, data: bytes, *, fin: bool = False, timeout: float | None = None) -> None:
        if self._cancelled:
            raise ConnectionResetError("cancelled")
        if self._sent_fin:
            raise RuntimeError("send after fin")
        assert self._other is not None, "attach() before send()"
        self.sent.append((data, fin))
        if data:
            await self._other._incoming.put(data)
        if fin:
            self._sent_fin = True
            await self._other._incoming.put(None)

    async def recv(self, *, timeout: float | None = None):
        if self._cancelled:
            raise ConnectionResetError("cancelled")
        if timeout is not None:
            return await asyncio.wait_for(self._incoming.get(), timeout)
        return await self._incoming.get()

    def cancel(self, reason: str = "cancelled") -> None:
        self._cancelled = True
        self.cancel_reason = reason


def make_pair(
    mode: Mode,
    method: str = "M",
    *,
    config: ChannelConfig | None = None,
    deadline_at_ini: float | None = None,
    deadline_at_acc: float | None = None,
) -> tuple[Channel, Channel, FakeByteStream, FakeByteStream]:
    """Return (initiator, acceptor, s_ini, s_acc) wired to each other."""
    s_ini = FakeByteStream(peer_id="acceptor")
    s_acc = FakeByteStream(peer_id="initiator")
    s_ini.attach(s_acc)

    hello = ChannelHello(mode=mode, method=method)
    s_acc.open_payload = hello.encode()

    codec = RawCodec()
    ini = Channel(
        s_ini,
        hello,
        codec,
        role="initiator",
        config=config,
        deadline_at=deadline_at_ini,
    )
    acc = Channel(
        s_acc,
        hello,
        codec,
        role="acceptor",
        config=config,
        deadline_at=deadline_at_acc,
    )
    return ini, acc, s_ini, s_acc


class TestConstructor:
    def test_rejects_unknown_role(self):
        s = FakeByteStream()
        hello = ChannelHello(mode=Mode.UNARY, method="M")
        with pytest.raises(ValueError, match="role"):
            Channel(s, hello, RawCodec(), role="sideways")

    def test_rejects_non_hello(self):
        s = FakeByteStream()
        with pytest.raises(TypeError):
            Channel(s, object(), RawCodec(), role="initiator")

    @pytest.mark.parametrize(
        "bad_cfg",
        [
            {"max_message_bytes": 0},
            {"max_message_bytes": 64 * 1024 * 1024 + 1},
            {"max_fragments": 0},
            {"max_fragments": 65537},
            {"max_chunk_bytes": 69},  # below PREFIX_LEN + 64
            {"max_chunk_bytes": 60 * 1024 + 1},
            {"terminal_fin_timeout": 0},
            {"terminal_fin_timeout": 60},
        ],
    )
    def test_rejects_bad_config(self, bad_cfg):
        with pytest.raises(ValueError):
            ChannelConfig(**bad_cfg)

    def test_default_config_is_valid(self):
        ChannelConfig()  # must not raise

    @pytest.mark.parametrize(
        "mode,role",
        [
            (m, r)
            for m in (
                Mode.UNARY,
                Mode.CLIENT_STREAM,
                Mode.SERVER_STREAM,
                Mode.BIDI,
                Mode.DATAGRAM,
            )
            for r in ("initiator", "acceptor")
        ],
    )
    def test_all_mode_role_combinations_construct(self, mode, role):
        s = FakeByteStream()
        hello = ChannelHello(mode=mode, method="" if mode is Mode.DATAGRAM else "M")
        Channel(s, hello, RawCodec(), role=role)  # must not raise


# ──────────────────────────────────────────────────────────────────────────
# Mode enforcement: limits
# ──────────────────────────────────────────────────────────────────────────


class TestModeLimits:
    @pytest.mark.asyncio
    async def test_unary_initiator_sends_once(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"one")
        with pytest.raises(ProtocolError) as exc:
            await ini.send(b"two")
        assert exc.value.status is Status.FAILED_PRECONDITION

    @pytest.mark.asyncio
    async def test_unary_acceptor_sends_once(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await acc.send(b"one")
        with pytest.raises(ProtocolError) as exc:
            await acc.send(b"two")
        assert exc.value.status is Status.FAILED_PRECONDITION

    @pytest.mark.asyncio
    async def test_client_stream_acceptor_sends_once(self):
        ini, acc, _, _ = make_pair(Mode.CLIENT_STREAM)
        await acc.send(b"resp")
        with pytest.raises(ProtocolError) as exc:
            await acc.send(b"resp2")
        assert exc.value.status is Status.FAILED_PRECONDITION

    @pytest.mark.asyncio
    async def test_server_stream_initiator_sends_once(self):
        ini, acc, _, _ = make_pair(Mode.SERVER_STREAM)
        await ini.send(b"req")
        with pytest.raises(ProtocolError) as exc:
            await ini.send(b"req2")
        assert exc.value.status is Status.FAILED_PRECONDITION

    @pytest.mark.asyncio
    async def test_datagram_acceptor_cannot_send(self):
        ini, acc, _, _ = make_pair(Mode.DATAGRAM)
        with pytest.raises(ProtocolError) as exc:
            await acc.send(b"nope")
        assert exc.value.status is Status.FAILED_PRECONDITION
        assert "DATAGRAM" in exc.value.detail

    @pytest.mark.asyncio
    async def test_datagram_initiator_multiple_sends_allowed(self):
        ini, acc, _, _ = make_pair(Mode.DATAGRAM)
        await ini.send(b"a")
        await ini.send(b"b")
        await ini.send(b"c")
        assert ini._send_count == 3

    @pytest.mark.asyncio
    async def test_bidi_both_sides_unbounded(self):
        ini, acc, _, _ = make_pair(Mode.BIDI)
        for i in range(10):
            await ini.send(f"i{i}".encode())
            await acc.send(f"a{i}".encode())
        assert ini._send_count == 10
        assert acc._send_count == 10


class TestSendRecvBasics:
    @pytest.mark.asyncio
    async def test_unary_full_exchange(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"request", end=True)
        assert await acc.recv() == b"request"
        assert await acc.recv() is EOF
        await acc.send(b"response", end=True)
        assert await ini.recv() == b"response"
        assert await ini.recv() is EOF

    @pytest.mark.asyncio
    async def test_recv_after_remote_end_returns_none_repeatedly(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"x", end=True)
        await acc.recv()
        assert await acc.recv() is EOF
        assert await acc.recv() is EOF  # idempotent

    @pytest.mark.asyncio
    async def test_send_after_local_end_raises(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"x", end=True)
        with pytest.raises(ProtocolError) as exc:
            await ini.send(b"y")
        assert exc.value.status is Status.FAILED_PRECONDITION

    @pytest.mark.asyncio
    async def test_send_after_both_ended_raises_cancelled(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"x", end=True)
        await acc.recv()
        await acc.recv()
        await acc.send(b"y", end=True)
        await ini.recv()
        await ini.recv()
        with pytest.raises(ProtocolError) as exc:
            await ini.send(b"z")
        assert exc.value.status is Status.CANCELLED

    @pytest.mark.asyncio
    async def test_codec_roundtrip(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        payload = b"\x00\x01\x02with binary\xff\xfe"
        await ini.send(payload, end=True)
        assert await acc.recv() == payload

    @pytest.mark.asyncio
    async def test_large_message_roundtrips_via_fragments(self):
        cfg = ChannelConfig(max_chunk_bytes=200)
        ini, acc, _, _ = make_pair(Mode.UNARY, config=cfg)
        payload = bytes(range(256)) * 8  # 2048 B → multiple fragments
        await ini.send(payload, end=True)
        assert await acc.recv() == payload

    @pytest.mark.asyncio
    async def test_async_iteration_yields_messages_then_stops(self):
        ini, acc, _, _ = make_pair(Mode.CLIENT_STREAM)
        for i in range(3):
            await ini.send(f"m{i}".encode())
        await ini.end(Status.OK)
        received = []
        async for msg in acc:
            received.append(msg)
        assert received == [b"m0", b"m1", b"m2"]

    @pytest.mark.asyncio
    async def test_recv_message_returns_message_object(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"raw", end=True)
        msg = await acc.recv_message()
        assert msg is not None
        assert msg.data == b"raw"


class TestEndSemantics:
    @pytest.mark.asyncio
    async def test_end_ok_unary_requires_exact_sends(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        with pytest.raises(ProtocolError) as exc:
            await ini.end(Status.OK)
        assert exc.value.status is Status.FAILED_PRECONDITION
        assert "1/1" in exc.value.detail or "0/1" in exc.value.detail

    @pytest.mark.asyncio
    async def test_end_ok_after_one_send_succeeds(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"x")
        await ini.end(Status.OK)  # must not raise
        assert ini.send_closed

    @pytest.mark.asyncio
    async def test_send_with_end_true_fuses_operations(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"only", end=True)
        assert ini._send_count == 1
        assert ini._local_ended
        assert await acc.recv() == b"only"
        assert await acc.recv() is EOF

    @pytest.mark.asyncio
    async def test_end_with_error_status_still_allowed(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.end(Status.CANCELLED, "gave up")
        assert ini.send_closed

    @pytest.mark.asyncio
    async def test_end_twice_is_noop(self):
        ini, acc, _, _ = make_pair(Mode.BIDI)
        await ini.end(Status.OK)
        await ini.end(Status.OK)  # second call no-op
        assert ini.send_closed

    @pytest.mark.asyncio
    async def test_fail_ok_status_rejected(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        with pytest.raises(ProtocolError) as exc:
            await ini.fail(Status.OK)
        assert exc.value.status is Status.INVALID_ARGUMENT

    @pytest.mark.asyncio
    async def test_fail_sends_error_envelope(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.fail(Status.NOT_FOUND, "gone", detail=b"reason")
        with pytest.raises(RemoteError) as exc:
            await acc.recv()
        assert exc.value.status is Status.NOT_FOUND
        assert exc.value.detail == "gone"
        assert exc.value.error_detail == b"reason"

    @pytest.mark.asyncio
    async def test_remote_error_is_terminal(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.fail(Status.INTERNAL, "boom")
        with pytest.raises(RemoteError) as exc:
            await acc.recv()
        assert exc.value.status is Status.INTERNAL
        assert await acc.recv() is EOF

        # ──────────────────────────────────────────────────────────────────────────


# Deadline
# ──────────────────────────────────────────────────────────────────────────


class TestDeadline:
    @pytest.mark.asyncio
    async def test_expired_deadline_aborts_send(self):
        deadline = time.monotonic() - 1.0
        ini, acc, _, _ = make_pair(Mode.UNARY, deadline_at_ini=deadline)
        with pytest.raises(ProtocolError) as exc:
            await ini.send(b"x")
        assert exc.value.status is Status.DEADLINE_EXCEEDED

    @pytest.mark.asyncio
    async def test_expired_deadline_aborts_recv(self):
        deadline = time.monotonic() - 1.0
        ini, acc, _, _ = make_pair(Mode.UNARY, deadline_at_acc=deadline)
        with pytest.raises(ProtocolError) as exc:
            await acc.recv()
        assert exc.value.status is Status.DEADLINE_EXCEEDED

    @pytest.mark.asyncio
    async def test_remaining_s_decreases(self):
        deadline = time.monotonic() + 5.0
        ini, acc, _, _ = make_pair(Mode.UNARY, deadline_at_ini=deadline)
        r1 = ini.remaining_s()
        await asyncio.sleep(0.01)
        r2 = ini.remaining_s()
        assert r1 is not None and r2 is not None
        assert r2 < r1

    @pytest.mark.asyncio
    async def test_remaining_s_none_when_unset(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        assert ini.remaining_s() is None

    @pytest.mark.asyncio
    async def test_user_timeout_shorter_than_deadline_raises_deadline(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        with pytest.raises(ProtocolError) as exc:
            await acc.recv(timeout=0.01)
        assert exc.value.status is Status.DEADLINE_EXCEEDED
        # channel not aborted by a user timeout
        assert acc._terminal_error is None


class TestCancel:
    @pytest.mark.asyncio
    async def test_cancel_closes_both_sides(self):
        ini, acc, s_ini, _ = make_pair(Mode.BIDI)
        ini.cancel("user")
        assert ini.send_closed
        assert ini.recv_closed
        assert s_ini.cancel_reason == "user"

    @pytest.mark.asyncio
    async def test_send_after_cancel_raises_cancelled(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        ini.cancel()
        with pytest.raises(ProtocolError) as exc:
            await ini.send(b"x")
        assert exc.value.status is Status.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_is_idempotent(self):
        ini, acc, _, _ = make_pair(Mode.BIDI)
        ini.cancel()
        ini.cancel()  # must not raise


class TestAclose:
    @pytest.mark.asyncio
    async def test_aclose_after_clean_exchange_is_noop(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        await ini.send(b"x", end=True)
        await acc.recv()
        await acc.recv()
        await acc.send(b"y", end=True)
        await ini.recv()
        await ini.recv()
        await ini.aclose()  # both already closed
        await acc.aclose()

    @pytest.mark.asyncio
    async def test_aclose_ends_open_send_side(self):
        ini, acc, _, _ = make_pair(Mode.SERVER_STREAM)
        # server_stream ini sends once then aclose() should cleanly end
        await ini.send(b"x")
        await ini.aclose()

    @pytest.mark.asyncio
    async def test_async_context_manager_clean_exit(self):
        ini, acc, _, _ = make_pair(Mode.UNARY)
        async with ini:
            await ini.send(b"x", end=True)
        # context manager exit called aclose(), send side closed
        assert ini.send_closed

    @pytest.mark.asyncio
    async def test_async_context_manager_exception_cancels(self):
        ini, acc, s_ini, _ = make_pair(Mode.BIDI)
        with pytest.raises(RuntimeError):
            async with ini:
                raise RuntimeError("boom")
        assert ini.send_closed
        assert s_ini.cancel_reason == "aborted"


# ──────────────────────────────────────────────────────────────────────────
# open_channel / accept_channel
# ──────────────────────────────────────────────────────────────────────────


class TestOpenAccept:
    @pytest.mark.asyncio
    async def test_accept_channel_decodes_hello(self):
        s_ini, s_acc = FakeByteStream(), FakeByteStream()
        s_ini.attach(s_acc)
        hello = ChannelHello(mode=Mode.UNARY, method="M")
        s_acc.open_payload = hello.encode()
        acc = await accept_channel(s_acc, RawCodec())
        assert acc.role == "acceptor"
        assert acc.mode is Mode.UNARY

    @pytest.mark.asyncio
    async def test_accept_channel_rejects_bad_hello(self):
        s_acc = FakeByteStream()
        s_acc.open_payload = b"\xff\xff\xffgarbage"
        with pytest.raises(ProtocolError):
            await accept_channel(s_acc, RawCodec())
        assert s_acc.cancel_reason == "bad_hello"

    @pytest.mark.asyncio
    async def test_open_channel_roles(self):
        s_ini, s_acc = FakeByteStream(), FakeByteStream()
        s_ini.attach(s_acc)
        hello = ChannelHello(mode=Mode.BIDI, method="M")
        s_acc.open_payload = hello.encode()
        ini = await open_channel(s_ini, hello, RawCodec())
        assert ini.role == "initiator"
        assert ini.mode is Mode.BIDI


class TestWireErrorPaths:
    @pytest.mark.asyncio
    async def test_peer_fin_without_terminal_aborts(self):
        ini, acc, s_ini, s_acc = make_pair(Mode.BIDI)
        # peer sends FIN with no END first
        await s_acc.send(b"", fin=True)
        with pytest.raises(ProtocolError) as exc:
            await ini.recv()
        assert exc.value.status is Status.MALFORMED

    @pytest.mark.asyncio
    async def test_data_after_terminal_aborts(self):
        ini, acc, s_ini, s_acc = make_pair(Mode.BIDI)
        # Build a proper END then stray DATA — send the END, then data

        from libs.proto.envelope import (
            Envelope,
            encode_envelope,
            make_end_headers,
        )

        end_env = Envelope(
            MsgType.END,
            headers=make_end_headers(Status.OK),
        )
        data_env = Envelope(MsgType.DATA, payload=b"stray")
        await s_acc.send(encode_envelope(end_env))
        await s_acc.send(encode_envelope(data_env))
        with pytest.raises(ProtocolError) as exc:
            await ini.recv()
        assert exc.value.status is Status.MALFORMED

    @pytest.mark.asyncio
    async def test_unary_ok_end_requires_exactly_one_message(self):
        from libs.proto.envelope import (
            Envelope,
            encode_envelope,
            make_end_headers,
        )

        ini, acc, s_ini, s_acc = make_pair(Mode.UNARY)
        end_env = Envelope(MsgType.END, headers=make_end_headers(Status.OK))
        await s_ini.send(encode_envelope(end_env))  # was s_acc.send — inverted
        with pytest.raises(ProtocolError) as exc:
            await acc.recv()
        assert exc.value.status is Status.MALFORMED
        assert "expected 1 message" in exc.value.detail


class TestStreamingRoundtrips:
    @pytest.mark.asyncio
    async def test_server_stream_sends_n_recv_one(self):
        ini, acc, _, _ = make_pair(Mode.SERVER_STREAM)
        await ini.send(b"req", end=True)
        assert await acc.recv() == b"req"
        assert await acc.recv() is EOF
        for i in range(5):
            await acc.send(f"part{i}".encode())
        await acc.end(Status.OK)

        received = []
        while True:
            m = await ini.recv()
            if m is EOF:
                break
            received.append(m)
        assert received == [f"part{i}".encode() for i in range(5)]

    @pytest.mark.asyncio
    async def test_client_stream_sends_n_recv_one(self):
        ini, acc, _, _ = make_pair(Mode.CLIENT_STREAM)
        for i in range(4):
            await ini.send(f"part{i}".encode())
        await ini.end(Status.OK)

        received = []
        while True:
            m = await acc.recv()
            if m is EOF:
                break
            received.append(m)
        assert received == [f"part{i}".encode() for i in range(4)]

        await acc.send(b"done", end=True)
        assert await ini.recv() == b"done"
        assert await ini.recv() is EOF

    @pytest.mark.asyncio
    async def test_bidi_echo(self):
        ini, acc, _, _ = make_pair(Mode.BIDI)

        async def echo():
            while True:
                msg = await acc.recv()
                if msg is EOF:
                    break
                await acc.send(msg)
            await acc.end(Status.OK)

        echo_task = asyncio.create_task(echo())

        for i in range(3):
            await ini.send(f"m{i}".encode())
            assert await ini.recv() == f"m{i}".encode()
        await ini.end(Status.OK)

        assert await ini.recv() is EOF
        await echo_task


class TestOversize:
    @pytest.mark.asyncio
    async def test_send_rejects_oversize_message(self):
        cfg = ChannelConfig(max_message_bytes=100)
        ini, acc, _, _ = make_pair(Mode.UNARY, config=cfg)
        with pytest.raises(ProtocolError) as exc:
            await ini.send(b"x" * 101)
        assert exc.value.status is Status.RESOURCE_EXHAUSTED

    @pytest.mark.asyncio
    async def test_recv_rejects_oversize_reassembled_message(self):
        cfg_ini = ChannelConfig(max_message_bytes=10 * 1024)
        cfg_acc = ChannelConfig(max_message_bytes=500)
        ini, acc, _, _ = make_pair(Mode.BIDI)
        # rebuild with different per-side configs
        ini._config = cfg_ini
        acc._config = cfg_acc
        from libs.proto.fragment import Reassembler

        acc._reassembler = Reassembler(500, DEFAULT_MAX_FRAGMENTS)

        await ini.send(b"y" * 1000)
        with pytest.raises(ProtocolError) as exc:
            await acc.recv()
        assert exc.value.status is Status.RESOURCE_EXHAUSTED


class TestWireShape:
    @pytest.mark.asyncio
    async def test_send_produces_data_envelope_then_end(self):
        from libs.proto.envelope import decode_envelope

        ini, acc, s_ini, _ = make_pair(Mode.UNARY)
        await ini.send(b"x", end=True)
        kinds = [decode_envelope(raw).type for raw, _ in s_ini.sent]
        assert kinds == [MsgType.DATA, MsgType.END]

    @pytest.mark.asyncio
    async def test_terminal_envelope_carries_fin(self):
        ini, acc, s_ini, _ = make_pair(Mode.UNARY)
        await ini.send(b"x", end=True)
        assert s_ini.sent[-1][1] is True  # fin flag on END

    @pytest.mark.asyncio
    async def test_non_terminal_envelopes_have_no_fin(self):
        ini, acc, s_ini, _ = make_pair(Mode.SERVER_STREAM)
        await ini.send(b"x")
        await ini.end(Status.OK)
        for _raw, fin in s_ini.sent[:-1]:
            assert fin is False
        assert s_ini.sent[-1][1] is True
