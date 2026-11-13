"""tests/test_capchain.py — TLS 1.3 mTLS + SPIFFE + capchain, one wire format."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Literal, Mapping

from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

import pytest
import libs.capchain as cc

from local_pki import NodeSpec, PKI
from pydantic import BaseModel, Field, field_validator, model_validator

from aegis.clock import (
    Clock,
    ClockSkew,
    require_within_skew,
    SystemClock,
)
from libs.transport.stream_session import (
    Stream,
    StreamError,
    Transport,
    TransportConfig,
    TransportError,
)
from libs.transport.tls import TlsConnection, TransportSetupError



log = logging.getLogger(__name__)

ENROLL_ENDPOINT = "/aegis/v1/enroll"
ISSUE_ENDPOINT  = "/aegis/v1/issue"
INVOKE_ENDPOINT = "/aegis/v1/invoke"

EXPECTED_SESSION = "test-session"
EXPECTED_TASK    = "test-task"

pytestmark = pytest.mark.asyncio


@pytest.fixture
def pki(tmp_path):
    return PKI(tmp_path, ["node-1", "node-2", "gateway"], "aegis-test")


@pytest.fixture
def server_node(pki):
    return pki.make_node("node-1", "127.0.0.1", 0)


@pytest.fixture
def client_node(pki):
    return pki.make_node("node-2", "127.0.0.1", 0)

@pytest.fixture
def gateway_node(pki):
    return pki.make_node("gateway", "127.0.0.1", 0)

_OK_DOC = 0x00
_ERR    = 0x01
_OK_RAW = 0x02

_CODE_MAX   = 48
_DETAIL_MAX = 512

def _safe_code(code: object) -> str:
    s = "".join(
        c for c in str(code) if c.isascii() and (c.isalnum() or c == "_")
    )[:_CODE_MAX]
    return s or "INTERNAL"


def encode_ok_doc(doc: dict) -> bytes:
    return bytes([_OK_DOC]) + cc.encode(doc)


def encode_ok_raw(blob: bytes) -> bytes:
    return bytes([_OK_RAW]) + blob


def encode_err(code: object, detail: object = "") -> bytes:
    return (
        bytes([_ERR])
        + _safe_code(code).encode("ascii")
        + b"\x00"
        + str(detail).encode("utf-8", "replace")[:_DETAIL_MAX]
    )


@dataclass(frozen=True, slots=True)
class Ok:
    doc: Optional[dict] = None
    raw: Optional[bytes] = None


@dataclass(frozen=True, slots=True)
class Err:
    code: str
    detail: str


def decode(raw: bytes) -> Ok | Err:
    """The only decoder. Raises TransportSetupError on malformed frames."""
    if not raw:
        raise TransportSetupError("EMPTY_RESPONSE")
    tag, body = raw[0], raw[1:]

    if tag == _OK_DOC:
        return Ok(doc=cc.decode(body))

    if tag == _OK_RAW:
        return Ok(raw=body)

    if tag == _ERR:
        code_b, sep, detail_b = body.partition(b"\x00")
        if not sep or not code_b:
            raise TransportSetupError("BAD_RESPONSE", "malformed error frame")
        if not all(
            0x41 <= b <= 0x5A or 0x30 <= b <= 0x39 or b == 0x5F for b in code_b
        ):
            raise TransportSetupError("BAD_RESPONSE", code_b.hex()[:32])
        return Err(
            code_b.decode("ascii"),
            detail_b.decode("utf-8", "replace"),
        )

    raise TransportSetupError("UNKNOWN_STATUS", f"0x{tag:02x}")



class RemoteError(Exception):
    """Server processed the request and rejected it. Connection is fine."""
    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Capability:
    raw: bytes
    jti: str
    run_id: str
    task_id: str
    tools: frozenset[str]
    audience: frozenset[str]
    budget_micros: int
    expires_at: int

    @classmethod
    def parse(cls, raw: bytes) -> "Capability":
        leaf = cc.Token.decode(raw).leaf.body()
        scope = leaf["scope"]
        return cls(
            raw=raw,
            jti=leaf["jti"],
            run_id=leaf["sid"],
            task_id=leaf["task"],
            tools=frozenset(scope["tools"]),
            audience=frozenset(scope.get("audience", [])),
            budget_micros=int(scope["budget"]),
            expires_at=int(leaf["exp"]),
        )

    def remaining(self, now: Optional[int] = None) -> int:
        return self.expires_at - (now if now is not None else int(time.time()))

    def expired(self, now: Optional[int] = None) -> bool:
        return self.remaining(now) <= 0

    def permits(self, tool: str) -> bool:
        return "*" in self.tools or tool in self.tools

    def permits_verifier(self, verifier_id: str) -> bool:
        return "*" in self.audience or verifier_id in self.audience


async def _wire_send(stream: Stream, payload: bytes, *, timeout: float = 1.0) -> None:
    try:
        await asyncio.wait_for(
            stream.send(payload, fin=True, timeout=timeout),
            timeout + 0.5,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        try:
            stream.cancel("send_failed")
        except Exception:
            pass


async def send_ok_doc(stream: Stream, doc: dict) -> None:
    await _wire_send(stream, encode_ok_doc(doc))


async def send_ok_raw(stream: Stream, blob: bytes) -> None:
    await _wire_send(stream, encode_ok_raw(blob))


async def send_error(stream: Stream, code: object, detail: object = "") -> None:
    await _wire_send(stream, encode_err(code, detail))


@asynccontextmanager
async def guarded(stream: Stream, *, where: str):
    """Wrap every handler body. Guarantees the peer gets a status byte, or
    the stream is cancelled (so bump() terminates) — never a silent hang."""
    try:
        yield
    except asyncio.CancelledError:
        raise
    except StreamError as exc:
        if exc.code in ("SEND_CLOSED", "RESET", "CONN_CLOSED"):
            return                                  # peer already knows
        await send_error(stream, exc.code, exc.detail)
    except (cc.RejectError, cc.EntitlementError, TransportSetupError) as exc:

        await send_error(
            stream,
            getattr(exc, "code", type(exc).__name__),
            getattr(exc, "detail", str(exc)),
        )
    except ClockSkew as exc:
        await send_error(stream, "POP_STALE", str(exc))
    except asyncio.TimeoutError:
        await send_error(stream, "TIMEOUT", "")
    except Exception as exc:
        await send_error(stream, "INTERNAL", type(exc).__name__)
        raise                                       # done-callback logs traceback


CostFn = Callable[[cc.Call, cc.ServerContext, cc.Verdict], int]
SettleFn = Callable[[bytes], int]
Handler = Callable[[bytes], Awaitable[bytes]]



class ToolRegistry:
    """Declares invokable tools with a reserve-cost and a settle-cost.

    `cost` must be an upper bound on the real cost: the reservation is what
    the ledger holds; settlement adjusts it, it cannot claw back work that
    already ran.
    """

    def __init__(self) -> None:
        self._tools: dict[str, tuple[CostFn, Handler, SettleFn]] = {}

    def register(
        self,
        resource: str,
        action: str,
        *,
        cost: int | CostFn,
        handler: Handler,
        settle: Optional[SettleFn] = None,
    ) -> None:
        key = f"{resource}:{action}"
        if key in self._tools:
            raise ValueError(f"tool already registered: {key}")
        cost_fn: CostFn = cost if callable(cost) else (lambda *_, c=cost: c)
        settle_fn: SettleFn = settle or (lambda _result: 0)
        self._tools[key] = (cost_fn, handler, settle_fn)

    def cost_model(self, call: cc.Call, context: cc.ServerContext, verdict: cc.Verdict) -> int:
        entry = self._tools.get(call.tool)
        if entry is None:
            raise cc.error(cc.Code.SCOPE_MISMATCH, f"unknown tool {call.tool}")
        return entry[0](call, context, verdict)

    def resolve(self, tool: str) -> tuple[Handler, SettleFn]:
        entry = self._tools.get(tool)
        if entry is None:
            raise cc.error(cc.Code.SCOPE_MISMATCH, f"unknown tool {tool}")
        return entry[1], entry[2]



class ScopeConfig(BaseModel):
    tools: list[str] = Field(min_length=1)
    domains: list[str] = Field(default_factory=list)
    audience: list[str] = Field(min_length=1)
    budget_micros: int = Field(ge=0)

    def to_scope(self) -> "cc.Scope":
        return cc.Scope(
            tools=frozenset(self.tools),
            budget_micros=self.budget_micros,
            audience=frozenset(self.audience),
            domains=frozenset(self.domains),
        )

class IssuerLimits(BaseModel):
    max_ttl_seconds: int = Field(gt=0, le=86400, default=10)
    max_delegation_depth: int = Field(ge=0, le=15, default=1)
    allowed_models: list[Literal["key_bound", "peer_bound"]]
    max_scope: ScopeConfig



@dataclass
class ServerHandle:
    node: NodeSpec
    clock: Clock
    governor_key: cc.CapChainKey         # signs tokens
    enrollment_key_obj: cc.CapChainKey   # signs receipts (separate)

    port: int = 0
    tls: dict[str, bytes] = field(default_factory=dict)
    tasks: list[asyncio.Task] = field(default_factory=list)
    by_kind: dict[str, asyncio.Queue] = field(
        default_factory=lambda: defaultdict(asyncio.Queue)
    )
    live: list[Transport] = field(default_factory=list)
    issue_audience: frozenset[str] = frozenset()
    issue_budget_micros: int = 1_000_000
    issuer: IssuerLimits | None = None

    _HANDLERS = {
        ENROLL_ENDPOINT: "_handle_enroll",
        ISSUE_ENDPOINT:  "_handle_issue",
        INVOKE_ENDPOINT: "_handle_invoke",
    }


    @property
    def name(self) -> str:
        return self.node.name
    
    @property
    def enrollment_verifier(self) -> bytes:
        return self.enrollment_key_obj.public_key
    
    @property
    def spiffe_id(self):
        return self.node.spiffe_id

    async def next(self, kind: str, timeout: float = 5.0) -> Stream:
        _, s = await asyncio.wait_for(self.by_kind[kind].get(), timeout)
        return s

    def _on_task_done(self, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.exception("stream handler crashed", exc_info=exc)
    
    async def close(self) -> None:
        for tr in self.live:
            if not tr.closed:
                try:
                    await asyncio.wait_for(tr.close("test_done"), 2.0)
                except Exception:
                    pass
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

    async def accept(self, transport: Transport, stream: Stream) -> None:
        await self.by_kind[stream.kind].put((transport, stream))
        name = self._HANDLERS.get(stream.kind)
        if name is None:
            stream.cancel(f"unknown_kind:{stream.kind}")
            return
        task = asyncio.create_task(getattr(self, name)(stream))
        task.add_done_callback(self._on_task_done)
        self.tasks.append(task)

    async def _handle_enroll(self, stream: Stream) -> None:
        async with guarded(stream, where="enroll"):
            peer_id = stream.peer_id
            binding = self.tls.get(peer_id)
            if binding is None:
                await send_error(stream, "NO_BINDING", peer_id)
                return
            req = decode(stream.open_token)
            if not isinstance(req, Ok) or req.raw is None:
                await send_error(stream, "BAD_REQUEST", "expected proof blob")
                return
       
            now_s = self.clock.now_seconds()
            proof = req.raw
            signed = cc.Signed.decode(proof)
            body = cc.decode(signed.body_raw)
            proof_ts = body.get("ts")
            if not isinstance(proof_ts, int) or isinstance(proof_ts, bool):
                raise ClockSkew("enrollment proof has no integer ts field")
            require_within_skew(
                proof_ts, now_s, self.node.enrollment_max_skew,
                what="enrollment proof timestamp",
            )
            
            proof_cnf = cc.verify_enrollment(
                proof,
                issuer_id=self.node.spiffe_id,
                channel_binding=binding,
                now=now_s,
                max_skew=self.node.enrollment_max_skew,
            )

            ttl_seconds=86400 * 7
            receipt = cc.make_enrollment_receipt(
                self.enrollment_key_obj,
                holder=peer_id, 
                cnf=proof_cnf,
                ttl_seconds=ttl_seconds,
                now=now_s,
            )
            enrolled =  cc.EnrolledKey(
                holder=peer_id,
                key_thumbprint=proof_cnf,
                receipt=receipt,
                valid_until=now_s + ttl_seconds
            )
            await send_ok_doc(stream, {
                "key_thumbprint": enrolled.key_thumbprint,
                "holder":         enrolled.holder,
                "receipt":        cc.b64e(enrolled.receipt),   
                "valid_until": enrolled.valid_until
            })

    async def _handle_issue(self, stream: Stream) -> None:
        async with guarded(stream, where="issue"):

            req = decode(stream.open_payload)
            if not isinstance(req, Ok) or req.doc is None:
                await send_error(stream, "BAD_REQUEST", "expected request doc")
                return
            doc = req.doc
            expected_fields = {
                "holder", "cnf", "receipt", "valid_until",
                "resource", "session_id", "task",
                "scope", "ttl_seconds",
            }
            requested_scope = cc.Scope.from_body(doc["scope"])
            requested_ttl = int(doc["ttl_seconds"])
    
            if set(doc) != expected_fields:
                await send_error(stream, "BAD_REQUEST", f"fields={sorted(doc)}")
                return
            
            scope = cc.Scope(
                tools=frozenset({"payments:read", "payments:write"}),
                budget_micros=self.issue_budget_micros,
                audience=self.issue_audience or frozenset({self.node.spiffe_id}),
            )
            if not doc["resource"] or not scope.allows_tool(doc["resource"]):
                await send_error(stream, "NO_SCOPE", doc["resource"])
                return
            # Bootstrap/limits check
            
            if requested_ttl > self.issuer.max_ttl_seconds:
                await send_error(stream, "TTL_TOO_LONG", "")
                return
            if not requested_scope.is_subset_of(self.issuer.max_scope.to_scope()):  
                await send_error(stream, "SCOPE_WIDENED", "")
                return

            holder = doc["holder"]
            cnf = doc["cnf"]
            if holder != stream.peer_id:
                await send_error(stream, "HOLDER_MISMATCH", holder)
                return
            if not doc.get("receipt"):
                await send_error(stream, "NOT_ENROLLED", "")
                return
            receipt = cc.b64d(doc["receipt"])
            
            receipt = cc.b64d(doc["receipt"])
            rolled = cc.EnrolledKey(
                holder=holder,
                key_thumbprint=cnf,
                receipt=receipt,
                valid_until=int(doc["valid_until"]),
            )
            try:
                ttl_seconds=3600
                max_depth: int = 1
                
                token_bytes =  cc.mint(
                    root_key=self.governor_key, # type: ignore
                    issuer=self.node.spiffe_id,
    
                    holder=holder,
                    enrolled_key=rolled,
                    enrollment_verifier=self.enrollment_verifier,                 
                    cnf=cnf,
                    session_id=doc["session_id"],
                    task=doc["task"],
                    scope=scope,
                    ttl_seconds=ttl_seconds,
                    now=self.clock.now_seconds(),
                    max_depth=max_depth,
                ).encode()

            except cc.RejectError as exc:
                await send_error(stream, exc.code, exc.detail)
                return
            await send_ok_raw(stream, token_bytes)

 

@dataclass
class ClientHandle:
    clock: Clock
    node:NodeSpec
    key: cc.CapChainKey
    binding: bytes
    transport: Transport
    active_stream: Optional[Stream] = None
    receipt: Optional[str] = None       # base64 string
    valid_until: Optional[int] = None

    @classmethod
    def new(cls, node, clock, binding, transport):
        return cls(
            node=node, clock=clock, binding=binding, transport=transport,
            key=cc.CapChainKey.generate(agent_id=node.spiffe_id),
        )

    @property
    def peer_id(self) -> str:
        return self.transport.peer_id

    @property
    def spiffe_id(self) -> str:
        return self.node.spiffe_id

    @property
    def thumbprint(self) -> str:
        return self.key.thumbprint
    @property
    def name(self) -> str:
        return self.node.name
    
    @property
    def public_key(self) -> bytes:
        return self.key.public_key

    def make_proof(self, issuer_id: str) -> bytes:
        return cc.make_enrollment(
            self.key,
            issuer_id=issuer_id,
            channel_binding=self.binding,
            now=self.clock.now_seconds(),
        )

    async def open_stream(self, kind, payload=b"", *, token=b"", pop=b""):
        self.active_stream = await self.transport.open_stream(
            kind=kind, payload=payload, token=token, pop=pop,
        )
        return self.active_stream

    async def close_stream(self) -> None:
        assert self.active_stream
        await self.active_stream.send(b"", fin=True)

    async def bump(self, timeout: float = 5.0) -> bytes:
        assert self.active_stream
        chunks: list[bytes] = []
        while (c := await self.active_stream.recv(timeout=timeout)) is not None:
            chunks.append(c)
        return b"".join(chunks)

    async def _request(self,  kind, payload=b"", token=b"", pop=b"", *, timeout: float = 10.0) -> Ok:
        await self.open_stream(kind=kind, payload=payload, token=token, pop=pop)
        
        await self.close_stream()
        raw = await self.bump(timeout)
        try:
            reply = decode(raw)
        except (TransportSetupError, cc.RejectError) as exc:
            raise RemoteError(
                getattr(exc, "code", "BAD_RESPONSE"),
                getattr(exc, "detail", str(exc)),
            ) from None
        if isinstance(reply, Err):
            raise RemoteError(reply.code, reply.detail)
        return reply

    async def enroll(self, *, timeout: float = 5.0) -> cc.EnrolledKey:
        proof = self.make_proof(self.peer_id)
        reply = await self._request(
            ENROLL_ENDPOINT,  token=encode_ok_raw(proof), timeout=timeout,
        )
        assert reply.doc
        self.receipt = reply.doc["receipt"]
        self.valid_until = reply.doc["valid_until"]

        assert reply.doc is not None
        return cc.EnrolledKey(
            receipt=self.receipt,
            valid_until=reply.doc["valid_until"],
            holder=reply.doc["holder"],
            key_thumbprint=reply.doc["key_thumbprint"],
        )

    async def request_token(self, resource: str) -> Capability:
        payload = encode_ok_doc({
            "holder": self.spiffe_id,
            "cnf": self.thumbprint,
            "receipt": self.receipt,
            "valid_until": self.valid_until,
            "resource": resource,
            "session_id": EXPECTED_SESSION,
            "task": EXPECTED_TASK,
            "scope": {
                "tools":    [resource],
                "budget":   100_000,
                "audience": [self.peer_id],   # peer_id during ISSUE == issuer spiffe
                "domains":  [],
            },
            "ttl_seconds": 300,
        })
        
        reply = await self._request(ISSUE_ENDPOINT, payload=payload)
        assert reply.raw is not None
        return Capability.parse(reply.raw)

    async def invoke(
        self,
        cap: Capability,
        *,
        resource: str,
        action: str,
        body: bytes,
        verifier_id: Optional[str] = None,
        session_id: Optional[str] = None,
        task: Optional[str] = None,
        timeout: float = 10.0,
    ) -> bytes:
        # 1. Client-side preflight (fails fast without a round-trip)
        if cap.expired(self.clock.now_seconds()):
            raise TransportError("TOKEN_EXPIRED", "")
        if not cap.permits(f"{resource}:{action}"):
            raise TransportError("SCOPE_MISMATCH", f"{resource}:{action}")
        verifier_id = verifier_id or self.peer_id
        if not cap.permits_verifier(verifier_id):
            raise TransportError("WRONG_AUDIENCE", verifier_id)

        # 2. PoP — signs the real body bytes, which is what the server will
        #    reconstruct from stream chunks. If you sign something else here,
        #    the server's `ph` (payload hash) check fails with POP_BINDING.
        pop = cc.make_pop(
            self.key,
            token=cap.raw,
            verifier_id=verifier_id,
            resource=resource,
            action=action,
            body=body,
            channel_binding=self.binding,
            now=self.clock.now_seconds(),
        )

        # 3. Metadata only. Body goes on the stream, not here.
        meta = encode_ok_doc({
            "resource":   resource,
            "action":     action,
            "session_id": session_id or cap.run_id,
            "task":       task or cap.task_id,
        })

        return await self._raw_invoke(pop, cap.raw, meta, body, timeout=timeout)


    async def _raw_invoke(
        self,
        pop: bytes,
        token: bytes,
        meta: bytes,
        body: bytes = b"",
        *,
        timeout: float = 10.0,
    ) -> bytes:
        """Low-level invoke: caller supplies the PoP and metadata. No preflight.

        Used by tests that need to exercise server-side rejections the
        client-side preflight would otherwise mask (wrong verifier, replay,
        body tampering, wrong session, etc.).
        """
        stream = await self.transport.open_stream(
            INVOKE_ENDPOINT, payload=meta, token=token, pop=pop,
        )
        self.active_stream = stream
        if body:
            await stream.send(body, timeout=timeout)
        await stream.send(b"", fin=True)

        chunks: list[bytes] = []
        while (chunk := await stream.recv(timeout=timeout)) is not None:
            chunks.append(chunk)
        raw = b"".join(chunks)

        try:
            reply = decode(raw)
        except (TransportSetupError, cc.RejectError) as exc:
            raise RemoteError(
                getattr(exc, "code", "BAD_RESPONSE"),
                getattr(exc, "detail", str(exc)),
            ) from None
        if isinstance(reply, Err):
            raise RemoteError(reply.code, reply.detail)
        assert reply.raw is not None
        return reply.raw


class Client:
    def __init__(self, node:NodeSpec, cfg: Optional[TransportConfig] = None) -> None:
        self.clock: Clock = SystemClock()
        self.node: NodeSpec = node
        self.key: cc.CapChainKey = cc.CapChainKey.generate(agent_id=self.node.spiffe_id)
        self.cfg = cfg
    @property
    def spiffe_id(self):
        return self.node.spiffe_id
    @property
    def name(self) -> str:
        return self.node.name
    
    @asynccontextmanager
    async def handler(self, port:int,   target: str, cfg:Optional[TransportConfig] = None):
        cfg = cfg or self.cfg
        r, w = await asyncio.open_connection(
            self.node.host, port, ssl=self.node.client_ssl,
        )
        try:
            tls = await TlsConnection.awrap(
                r, w, adapter=self.node.client_adapter(target),
            )
        except Exception:
            w.close()
            raise
        try:
            client_transport = await Transport.establish(
                tls, cfg , is_client=True, # type: ignore
            )
        except Exception:
            w.close()
            raise

        try:
            yield ClientHandle(
                key=self.key,
                node=self.node,
                transport=client_transport,
                clock=self.clock,
                binding=tls.channel_binding,
            )
        finally:
            try:
                await asyncio.wait_for(client_transport.close("test_done"), 2.0)
            except Exception:
                pass

@dataclass
class Broker:
    """Serves invoke. One instance per process."""

    node: NodeSpec
    gateway: cc.Gateway
    tools: ToolRegistry
    entitlements: cc.EntitlementTable          # NEW

    transport_config: TransportConfig = field(default_factory=TransportConfig)
    port: int = 0
    _server: Optional[asyncio.AbstractServer] = None     

    _tasks: list[asyncio.Task] = field(default_factory=list)
    _transports: list[Transport] = field(default_factory=list)

    @property
    def spiffe_id(self):
        return self.node.spiffe_id
    @property
    def name(self) -> str:
        return self.node.name
    
    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._on_connection,
            self.node.host, self.node.port,
            ssl=self.node.server_ssl,
        )
        port = self._server.sockets[0].getsockname()[1]
        log.info("broker listening on %s:%d", self.node.host, port)
        self.port = port
        return port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), 5.0)
            except asyncio.TimeoutError:
                pass
        for tr in self._transports:
            if not tr.closed:
                try:
                    await asyncio.wait_for(tr.close("broker_stop"), 2.0)
                except Exception:
                    pass
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _on_connection(self, reader, writer) -> None:
        try:
            tls = await TlsConnection.awrap(
                reader, writer, adapter=self.node.server_adapter(),
            )
        except Exception:
            writer.close()
            return
        try:
            transport = await Transport.establish(
                tls, self.transport_config, is_client=False,
            )
        except Exception:
            writer.close()
            return
        
        self._transports.append(transport)
        try:
            while True:
                stream = await transport.accept()
                binding = tls.channel_binding
                
                task = asyncio.create_task(self._dispatch(binding, stream))
                task.add_done_callback(self._on_task_done)
                self._tasks.append(task)
        except (StreamError, TransportError):
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("broker connection crashed peer=%s", transport.peer_id)

    def _on_task_done(self, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.exception("broker stream handler crashed", exc_info=exc)

    async def _dispatch(self,binding:bytes, stream: Stream) -> None:
        async with guarded(stream, where=stream.kind):
            handler = {
                INVOKE_ENDPOINT: self._handle_invoke,
            }.get(stream.kind)
            if handler is None:
                await send_error(stream, "UNKNOWN_ENDPOINT", stream.kind)
                return
            await handler(binding, stream)

    async def _handle_invoke(self, binding: bytes, stream: Stream) -> None:

        if stream.peer_id in self.gateway._policy.root_issuers:
            await send_error(stream, "ROLE_REQUIRED", stream.peer_id)
            return
        token = stream.open_token
        if not token:
            await send_error(stream, "BAD_REQUEST", "missing token")
            return
        pop: Optional[bytes] = stream.open_pop or None

        req = decode(stream.open_payload)
        if not isinstance(req, Ok) or req.doc is None:
            await send_error(stream, "BAD_REQUEST", "expected request doc")
            return
        doc = req.doc
        if set(doc) != {"resource", "action", "session_id", "task"}:
            await send_error(stream, "BAD_REQUEST", f"fields={sorted(doc)}")
            return
        chunks: list[bytes] = []
        while (chunk := await stream.recv()) is not None:
            chunks.append(chunk)
        body = b"".join(chunks)

        now = int(time.time())
        try:
            checked = self.entitlements.check(token, peer_id=stream.peer_id, now=now)
        except cc.EntitlementError as exc:
            await send_error(stream, exc.code, exc.detail)
            return


        call = cc.Call(resource=doc["resource"], action=doc["action"], body=body)
        context = cc.ServerContext(session_id=doc["session_id"], task=doc["task"])

        try:
            async with self.gateway.authorize(
                channel_binding=binding,
                peer_id=stream.peer_id,
                token=token,
                call=call,
                context=context,
                proof=pop,
                cost_model=self.tools.cost_model,
            ) as permit:
                # Token is authenticated here. Charge the holder's allowance
                # BEFORE dispatch so a rejected token never runs the tool.
                self.entitlements.admit(checked, now=now)
                handler, settle = self.tools.resolve(call.tool)
                await permit.mark_dispatched()
                result = await handler(body)
                await permit.settle(settle(result))
        except cc.RejectError as exc:
            await send_error(stream, exc.code, exc.detail)
            return

        await send_ok_raw(stream, result)
               

@asynccontextmanager 
async def transport_pair(
    server_node:NodeSpec,
    client_node:NodeSpec,
    gateway_node:NodeSpec,
    server_cfg: Optional[TransportConfig] = None,
    client_cfg: Optional[TransportConfig] = None,   
):
    server_cfg = server_cfg or TransportConfig()
    client_cfg = client_cfg or TransportConfig()    
    governor_key = cc.CapChainKey.generate(agent_id=server_node.spiffe_id)
    enrollment_key_obj = cc.CapChainKey.generate(agent_id=f"{server_node.spiffe_id}/enrollment")
 
    replay = cc.InMemoryReplayStore(ttl_seconds=300)
    ledger = cc.InMemoryBudgetLedger()
    revocation = cc.InMemoryRevocationStore()
    evidence = cc.InMemoryEvidenceLog()

    async def read_balance(body: bytes) -> bytes:
        return b'{"balance": 42}'
    
    tools = ToolRegistry()
    tools.register("payments", "read", cost=1000, handler=read_balance, settle=lambda result: 100)
    client_handler = Client(client_node, client_cfg)

    entitlements = cc.EntitlementTable({
        (server_node.spiffe_id, client_node.spiffe_id): cc.Entitlement(
            cnf=frozenset({client_handler.key.thumbprint}),
            tools=frozenset({"payments:read", "payments:write"}),
            audience=frozenset({gateway_node.spiffe_id}),
            max_budget_micros=1_000_000,
            max_ttl_seconds=3600,
            max_outstanding_budget_micros=3_000_000,
            max_live_tokens=100,
        ),
    })
    brocker = Broker(
        gateway=cc.Gateway(
            cfg=cc.GatewayConfig(
                replay=replay,
                ledger=ledger,
                revocation=revocation,
                evidence=evidence,
                agent_id=gateway_node.spiffe_id,
                roots=cc.TrustedRoots(
                    issuers={server_node.spiffe_id: governor_key.public_key},
                    enrollment_authority_key=enrollment_key_obj.public_key,
                ),
                policy=cc.Policy(
                    root_issuers=frozenset({server_node.spiffe_id}),
                edges=frozenset({
                    (server_node.spiffe_id, client_node.spiffe_id),    # (node-1, node-2)
    
                }),
                ),   
            )
        ),
        tools=tools,
        entitlements=entitlements,
        node=gateway_node,
    )
    server_handler = ServerHandle(
        node=server_node, clock=SystemClock(),
        governor_key=governor_key,
        enrollment_key_obj=enrollment_key_obj,
    
        issue_audience = frozenset({gateway_node.spiffe_id}),
    
        issuer = IssuerLimits(
        max_ttl_seconds=300,
        max_delegation_depth=1,
        allowed_models=["key_bound"],
        max_scope=ScopeConfig(
            tools=["payments:read", "payments:write"],
            domains=[],
            audience=[server_node.spiffe_id, gateway_node.spiffe_id],
            budget_micros=1_000_000,
        ),
    )
    )  

    async def on_conn(reader, writer):
        try:
            tls = await TlsConnection.awrap(
                reader, writer, adapter=server_node.server_adapter(),
            )
        except Exception:
            writer.close()
            return
        try:
            transport = await Transport.establish(tls, server_cfg, is_client=False)
        except Exception:
            writer.close()
            return
        server_handler.tls[tls.peer_id] = tls.channel_binding
        server_handler.live.append(transport)
        try:
            while True:
                stream = await transport.accept()
                await server_handler.accept(transport, stream)
        except (StreamError, TransportError):
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    server = await asyncio.start_server(
        on_conn, server_node.host, server_node.port, ssl=server_node.server_ssl,
    )
    await brocker.start()
    server_handler.port = server.sockets[0].getsockname()[1]
    server_handler.issue_audience=frozenset({gateway_node.spiffe_id})

    try:
        yield brocker, server_handler, client_handler
  
    finally:
        await brocker.stop()
        server.close()
        await server_handler.close()
        try:
            await asyncio.wait_for(server.wait_closed(), 5.0)
        except asyncio.TimeoutError:
            pass



async def test_01_enroll(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            enrolled = await ch.enroll()
            assert enrolled.holder == ch.spiffe_id
            assert enrolled.key_thumbprint == ch.thumbprint
            # assert key.key_thumbprint == ch.thumbprint
            # assert key.holder == ch.spiffe_id


async def test_02_issue(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")
            assert cap.permits("payments:read")
            assert cap.permits("payments:write")
            assert cap.permits_verifier(b.spiffe_id)
            assert not cap.expired()
            assert cap.run_id == EXPECTED_SESSION
            assert cap.task_id == EXPECTED_TASK


# ═══════════════════════ issue rejection tests ═══════════════════════

async def test_03_issue_out_of_scope(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            with pytest.raises(RemoteError) as ei:
                await ch.request_token("payments:delete")
            assert ei.value.code == "NO_SCOPE"
            assert not ch.transport.closed


async def test_04_issue_not_enrolled(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await ch.request_token("payments:read")
            assert ei.value.code == "NOT_ENROLLED"
            assert not ch.transport.closed


# ═══════════════════════ invoke happy path ═══════════════════════

async def test_05_invoke(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        # Phase 1 — enroll and issue against the issuer (server)
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        # Phase 2 — invoke against the broker (gateway), fresh TLS, same key
        async with c.handler(b.port, b.name, cfg) as ch:
            result = await ch.invoke(
                cap,
                resource="payments",
                action="read",
                body=b'{"id": 42}',
                verifier_id=b.spiffe_id,
            )
        assert b'"balance": 42' in result


# ═══════════════════════ invoke rejection tests ═══════════════════════

async def test_06_invoke_replay(server_node, client_node, gateway_node):
    """The same PoP is rejected the second time by the replay store."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            body = b'{"id": 42}'
            pop = c.key.make_pop(
                token=cap.raw,
                verifier_id=b.spiffe_id,
                resource="payments",
                action="read",
                body=body,
                channel_binding=ch.binding,
                now=c.clock.now_seconds(),
            )
            meta = encode_ok_doc({
                "resource":   "payments",
                "action":     "read",
                "session_id": EXPECTED_SESSION,
                "task":       EXPECTED_TASK,
            })

            # First use succeeds.
            r1 = await ch._raw_invoke(pop, cap.raw, meta, body)
            assert b'"balance": 42' in r1

            # Second use — same nonce, same everything — is REPLAY.
            with pytest.raises(RemoteError) as ei:
                await ch._raw_invoke(pop, cap.raw, meta, body)
            assert ei.value.code == "REPLAY"




async def test_06b_fresh_nonce_per_invoke(server_node, client_node, gateway_node):
    """Two invokes from the same client, same capability, same connection,
    must both succeed. Proves the nonce is fresh per PoP."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            # Same cap, same body, same everything — only the nonce differs.
            r1 = await ch.invoke(
                cap,
                resource="payments", action="read",
                body=b'{"id": 1}', verifier_id=b.spiffe_id,
            )
            r2 = await ch.invoke(
                cap,
                resource="payments", action="read",
                body=b'{"id": 1}', verifier_id=b.spiffe_id,
            )
            assert b'"balance": 42' in r1
            assert b'"balance": 42' in r2


async def test_06c_failed_invoke_burns_nonce(server_node, client_node, gateway_node):
    """A PoP that fails a policy check is still burned. Retrying the same
    PoP must fail with REPLAY, not with the original policy error."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            body = b'{"id": 42}'
            pop = c.key.make_pop(
                token=cap.raw,
                verifier_id=b.spiffe_id,
                resource="payments", action="read",
                body=body,
                channel_binding=ch.binding,
                now=c.clock.now_seconds(),
            )
            # Wrong session — fails after PoP verifies, nonce consumed
            meta_bad = encode_ok_doc({
                "resource": "payments", "action": "read",
                "session_id": "a-different-session",
                "task": EXPECTED_TASK,
            })
            with pytest.raises(RemoteError) as ei:
                await ch._raw_invoke(pop, cap.raw, meta_bad, body)
            assert ei.value.code == "WRONG_SESSION"

            # Retry with CORRECT session, SAME PoP — must be REPLAY,
            # not a fresh policy check. The nonce is already burned.
            meta_good = encode_ok_doc({
                "resource": "payments", "action": "read",
                "session_id": EXPECTED_SESSION,
                "task": EXPECTED_TASK,
            })
            with pytest.raises(RemoteError) as ei:
                await ch._raw_invoke(pop, cap.raw, meta_good, body)
            assert ei.value.code == "REPLAY"



async def test_07_invoke_body_tampered(server_node, client_node, gateway_node):
    """PoP signs body A but the stream carries body B → ph mismatch."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            pop = c.key.make_pop(
                token=cap.raw,
                verifier_id=b.spiffe_id,
                resource="payments",
                action="read",
                body=b'{"id": 42}',              # signs this
                channel_binding=ch.binding,
                now=c.clock.now_seconds(),
            )
            meta = encode_ok_doc({
                "resource":   "payments",
                "action":     "read",
                "session_id": EXPECTED_SESSION,
                "task":       EXPECTED_TASK,
            })

            with pytest.raises(RemoteError) as ei:
                await ch._raw_invoke(
                    pop, cap.raw, meta,
                    b'{"id": 99}',               # sends a different body
                )
            assert ei.value.code == "POP_BINDING"


async def test_08_invoke_unknown_tool(server_node, client_node, gateway_node):
    """Token permits the action, but the broker has no handler for it."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            # payments:write is in the issuer's scope but the broker's
            # ToolRegistry only knows payments:read.
            cap = await ch.request_token("payments:write")

        async with c.handler(b.port, b.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await ch.invoke(
                    cap,
                    resource="payments",
                    action="write",
                    body=b"",
                    verifier_id=b.spiffe_id,
                )
            assert ei.value.code == "SCOPE_MISMATCH"
            assert "unknown tool" in ei.value.detail


async def test_09_invoke_wrong_verifier(server_node, client_node, gateway_node):
    """PoP audience must equal the verifier's SPIFFE ID."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            body = b'{"id": 42}'
            pop = c.key.make_pop(
                token=cap.raw,
                verifier_id="spiffe://aegis-test/evil",   # not the gateway
                resource="payments",
                action="read",
                body=body,
                channel_binding=ch.binding,
                now=c.clock.now_seconds(),
            )
            meta = encode_ok_doc({
                "resource":   "payments",
                "action":     "read",
                "session_id": EXPECTED_SESSION,
                "task":       EXPECTED_TASK,
            })

            with pytest.raises(RemoteError) as ei:
                await ch._raw_invoke(pop, cap.raw, meta, body)
            assert ei.value.code == "POP_BINDING"


async def test_10_invoke_wrong_session(server_node, client_node, gateway_node):
    """The server-held session must match the token's sid."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            body = b'{"id": 42}'
            pop = c.key.make_pop(
                token=cap.raw,
                verifier_id=b.spiffe_id,
                resource="payments",
                action="read",
                body=body,
                channel_binding=ch.binding,
                now=c.clock.now_seconds(),
            )
            meta = encode_ok_doc({
                "resource":   "payments",
                "action":     "read",
                "session_id": "a-different-session",   # ≠ token.sid
                "task":       EXPECTED_TASK,
            })

            with pytest.raises(RemoteError) as ei:
                await ch._raw_invoke(pop, cap.raw, meta, body)
            assert ei.value.code == "WRONG_SESSION"


# ═══════════════════════ wire codec unit tests ═══════════════════════

async def test_11_wire_codec_roundtrip():
    """Every tag encodes and decodes symmetrically."""
    doc = {"resource": "payments", "session_id": "s", "task": "t"}
    reply = decode(encode_ok_doc(doc))
    assert isinstance(reply, Ok) and reply.doc == doc

    blob = b"\x00\x01\x02binary\xff"
    reply = decode(encode_ok_raw(blob))
    assert isinstance(reply, Ok) and reply.raw == blob

    reply = decode(encode_err("NO_SCOPE", "payments:delete"))
    assert isinstance(reply, Err)
    assert reply.code == "NO_SCOPE"
    assert reply.detail == "payments:delete"

async def test_12_wire_codec_rejects_malformed():
    """Malformed frames fail closed, never silently."""

    def _code(exc: BaseException) -> str:
        c = getattr(exc, "code", None)
        if c is not None:
            return str(c)
        return str(exc).partition(":")[0]

    with pytest.raises(TransportSetupError) as ei:
        decode(b"")
    assert _code(ei.value) == "EMPTY_RESPONSE"

    with pytest.raises(TransportSetupError) as ei:
        decode(b"\xffanything")
    assert _code(ei.value) == "UNKNOWN_STATUS"

    with pytest.raises(TransportSetupError) as ei:
        decode(b"\x01NO_SCOPE")
    assert _code(ei.value) == "BAD_RESPONSE"

    with pytest.raises(TransportSetupError) as ei:
        decode(b"\x01lowercase\x00detail")
    assert _code(ei.value) == "BAD_RESPONSE"

    with pytest.raises(TransportSetupError) as ei:
        decode(b"\x01\x00detail")
    assert _code(ei.value) == "BAD_RESPONSE"






async def test_14_expired_leaf_blocks_transport(tmp_path):
    """A leaf past its not_after cannot anchor a Transport, even when
    the CA is valid. Distinct from test_13: leaf validity and anchor
    validity are enforced in different places by the SSL stack, and a
    regression in either alone leaves a hole."""
    import ssl

    pki = PKI(tmp_path, ["node-1", "node-2", "gateway"], "aegis-test")
    server_node  = pki.make_node("node-1",  "127.0.0.1", 0,
                                 agent_not_after_seconds=-30)
    client_node  = pki.make_node("node-2",  "127.0.0.1", 0)
    gateway_node = pki.make_node("gateway", "127.0.0.1", 0)

    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        with pytest.raises(
            (ssl.SSLError, TransportSetupError, TransportError,
             ConnectionError, OSError)
        ) as ei:
            async with c.handler(s.port, s.name, cfg) as ch:
                pytest.fail(
                    f"Transport established with expired leaf; peer={ch.peer_id!r}"
                )

        code = getattr(ei.value, "code", None)
        detail = getattr(ei.value, "detail", None)
        text = " ".join(
            str(x) for x in (code, detail, ei.value) if x is not None
        ).upper()
        assert any(kw in text for kw in (
            "CERT", "CERTIFICATE", "EXPIRED", "VERIFY", "HANDSHAKE", "TLS",
        )), f"Transport failed but not for TLS reasons: {ei.value!r}"



async def test_13_expired_ca_blocks_transport(tmp_path):
    """An expired CA cannot anchor a Transport.

    Drives the same path as test_01: Client.handler -> TlsConnection.awrap
    -> Transport.establish. The failure can occur in any of those three
    stages depending on where the SSL library gives up first. What matters
    is that no Transport object is ever returned to the caller.
    """
    import ssl
    pki = PKI(
        tmp_path,
        ["node-1", "node-2", "gateway"],
        "aegis-test",
        ca_not_after_seconds_from_now=-60,      # CA expired one minute ago
    )
    server_node  = pki.make_node("node-1",  "127.0.0.1", 0)
    client_node  = pki.make_node("node-2",  "127.0.0.1", 0)
    gateway_node = pki.make_node("gateway", "127.0.0.1", 0)

    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        with pytest.raises(
            (ssl.SSLError, TransportSetupError, TransportError,
             ConnectionError, OSError)
        ) as ei:
            async with c.handler(s.port, s.name, cfg) as ch:
                # Reaching this line means Transport.establish returned a
                # live transport despite the CA being expired.
                pytest.fail(
                    f"Transport established with expired CA; peer={ch.peer_id!r}"
                )

        # Not every failure mode carries structured info on the exception
        # (TransportSetupError used to not, until it gained .code). Check
        # both the code attribute and the message so this works either way.
        code = getattr(ei.value, "code", None)
        detail = getattr(ei.value, "detail", None)
        text = " ".join(
            str(x) for x in (code, detail, ei.value) if x is not None
        ).upper()
        assert any(kw in text for kw in (
            "CERT", "CERTIFICATE", "EXPIRED", "VERIFY", "HANDSHAKE", "TLS",
        )), f"Transport failed but not for TLS reasons: {ei.value!r}"



async def test_15_stale_pop(server_node, client_node, gateway_node):
    """PoP older than max_skew is rejected before the nonce is consumed."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            body = b'{"id": 42}'
            stale_pop = c.key.make_pop(
                token=cap.raw,
                verifier_id=b.spiffe_id,
                resource="payments", action="read",
                body=body,
                channel_binding=ch.binding,
                now=c.clock.now_seconds() - 60,   # 60s ago, max_skew=30
            )
            meta = encode_ok_doc({
                "resource": "payments", "action": "read",
                "session_id": EXPECTED_SESSION, "task": EXPECTED_TASK,
            })
            with pytest.raises(RemoteError) as ei:
                await ch._raw_invoke(stale_pop, cap.raw, meta, body)
            assert ei.value.code == "POP_STALE"
    

async def test_16_evidence_logged(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            await ch.invoke(
                cap, resource="payments", action="read",
                body=b'{"id": 42}', verifier_id=b.spiffe_id,
            )

        records = await b.gateway.evidence.records()
        assert await  b.gateway.evidence.verify_integrity()

        # Admission + settlement
        assert len(records) == 2
        admit, settled = records
        assert admit.code == "OK"
        assert admit.cost_micros == 1000           # reserved
        assert settled.code == "SETTLED"
        assert settled.cost_micros == 100           # actual
        assert settled.related_id == admit.action_id



async def test_17_revoked_key_rejected(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        # Revoke the client's key before invoke.
        await b.gateway._revocation.revoke_key(ch.thumbprint)

        async with c.handler(b.port, b.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await ch.invoke(
                    cap, resource="payments", action="read",
                    body=b'{"id": 42}', verifier_id=b.spiffe_id,
                )
            assert ei.value.code == "REVOKED"



async def test_18_budget_exhausted(server_node, client_node, gateway_node):
    """The ledger caps cumulative spend, not just per-call size.

    With cost=1000 and settle=100, each successful call nets 100 micros
    of real spend against a 1,000-micro budget. So: one call succeeds
    (remaining 900), the second reserve needs 1000 and only 900 is left.
    """
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        s.issue_budget_micros = 1_000

        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            await ch.invoke(
                cap, resource="payments", action="read",
                body=b'{"id": 1}', verifier_id=b.spiffe_id,
            )
            with pytest.raises(RemoteError) as ei:
                await ch.invoke(
                    cap, resource="payments", action="read",
                    body=b'{"id": 1}', verifier_id=b.spiffe_id,
                )
            assert ei.value.code == "BUDGET_EXHAUSTED"

            # Pin down WHICH budget fired: the ledger, not the leaf cap.
            # Leaf cap still holds: 1000 <= 1000. The ledger is the one
            # that ran out (900 remaining, next reserve needs 1000).
            assert await b.gateway._ledger.remaining(cap.jti) == 900


async def test_19_replay_store_state(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        async with c.handler(b.port, b.name, cfg) as ch:
            await ch.invoke(
                cap, resource="payments", action="read",
                body=b'{"id": 1}', verifier_id=b.spiffe_id,
            )

        # The nonce the client used is now in the gateway's replay store.
        # A subsequent fresh invoke should still work (fresh nonce).
        async with c.handler(b.port, b.name, cfg) as ch:
            await ch.invoke(
                cap, resource="payments", action="read",
                body=b'{"id": 1}', verifier_id=b.spiffe_id,
            )




async def stolen_governor_key_plus_agent_identity(server_node, client_node, gateway_node):
    """Expected to PASS today. That pass is the vulnerability."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        attacker = cc.CapChainKey.generate(agent_id=client_node.spiffe_id)
        forged = cc.mint(
            s.governor_key,                                   # stolen governor key
            enrollment_verifier=b",",
            enrolled_key=b" ",
            issuer=server_node.spiffe_id,
            holder=client_node.spiffe_id,
            cnf=attacker.thumbprint,                 # attacker-chosen cnf, no enrollment
            session_id=EXPECTED_SESSION, task=EXPECTED_TASK,
            scope=cc.Scope(
                tools=frozenset({"payments:read", "payments:write", "payments:delete"}),
                budget_micros=10**12,
                audience=frozenset({b.spiffe_id}),
            ),
            ttl_seconds=86400, now=c.clock.now_seconds(), max_depth=1,
        ).encode()

        async with c.handler(b.port, b.name, cfg) as ch:   # attacker holds node-2's mTLS identity
            body = b'{"id": 1}'
            pop = attacker.make_pop(
                token=forged, verifier_id=b.spiffe_id,
                resource="payments", action="read", body=body,
                channel_binding=ch.binding, now=c.clock.now_seconds(),
            )
            meta = encode_ok_doc({"resource": "payments", "action": "read",
                                  "session_id": EXPECTED_SESSION, "task": EXPECTED_TASK})
            result = await ch._raw_invoke(pop, forged, meta, body)
        assert b'"balance": 42' in result


async def test_20_stolen_governor_key_attacker_cnf_rejected(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        # Attacker enrolls legitimately (they own client_node identity, so
        # they get a valid receipt for THEIR key)
        attacker = cc.CapChainKey.generate(agent_id=client_node.spiffe_id)
        async with c.handler(s.port, s.name, cfg) as ch:
            enrolled = await ch.enroll()   # receipt for c.key, not attacker.key

        # Attacker swaps in their own key + uses the cnf from a stolen receipt
        now = c.clock.now_seconds()
        forged = _forge(
            s,
            holder=client_node.spiffe_id,
            cnf=attacker.thumbprint,
            tools={"payments:read", "payments:write", "payments:delete"},
            budget=10**12,
            ttl=86400,
            now=now,
            audience=b.spiffe_id,
            receipt=cc.b64d(enrolled.receipt),
        )

        async with c.handler(b.port, b.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await _invoke_raw(ch, token=forged, signer=attacker,
                                  verifier_id=b.spiffe_id, now=now)
            assert ei.value.code == "CNF_NOT_REGISTERED"

async def stolen_governor_key_alone_rejected(server_node, client_node, gateway_node):
    """Expected to be REJECTED. If this passes, things are worse than I claimed."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        outsider = Client(server_node, cfg)          # mTLS identity is node-1, not the holder
        forged = cc.mint(
            s.governor_key,                                   # stolen governor key
            enrollment_verifier=b",",
            enrolled_key=b" ",
            issuer=server_node.spiffe_id,
            holder=client_node.spiffe_id,
            cnf=outsider.key.thumbprint,
            session_id=EXPECTED_SESSION, task=EXPECTED_TASK,
            scope=cc.Scope(tools=frozenset({"payments:read"}), budget_micros=10**6,
                           audience=frozenset({b.spiffe_id})),
            ttl_seconds=3600, now=outsider.clock.now_seconds(), max_depth=1,
        ).encode()

        async with outsider.handler(b.port, b.name, cfg) as ch:
            body = b'{"id": 1}'
            pop = outsider.key.make_pop(
                token=forged, verifier_id=b.spiffe_id,
                resource="payments", action="read", body=body,
                channel_binding=ch.binding, now=outsider.clock.now_seconds(),
            )
            meta = encode_ok_doc({"resource": "payments", "action": "read",
                                  "session_id": EXPECTED_SESSION, "task": EXPECTED_TASK})
            with pytest.raises(RemoteError):
                await ch._raw_invoke(pop, forged, meta, body)


def _forge(server: ServerHandle, *, holder: str, cnf: str, tools, budget: int,
           ttl: int, now: int, audience: str,
           receipt: bytes | None = None,
           session: str = EXPECTED_SESSION) -> bytes:
    """Forge a token as if the attacker holds the governor key."""
    if receipt is None:
        receipt = cc.make_enrollment_receipt(
            server.enrollment_key_obj,
            holder=holder,
            cnf=cnf,
            ttl_seconds=3600,
            now=now,
        )
    return cc.mint(
        server.governor_key,
        enrolled_key=cc.EnrolledKey(
            holder=holder,
            key_thumbprint=cnf,
            receipt=receipt,
            valid_until=now + 3600,
        ),
        enrollment_verifier=server.enrollment_verifier,
        issuer=server.spiffe_id,
        holder=holder,
        cnf=cnf,
        session_id=session,               # ← was EXPECTED_SESSION hardcoded
        task=EXPECTED_TASK,
        scope=cc.Scope(
            tools=frozenset(tools),
            budget_micros=budget,
            audience=frozenset({audience}),
        ),
        ttl_seconds=ttl,
        now=now,
        max_depth=1,
    ).encode()

async def _invoke_raw(ch, *, token: bytes, signer, verifier_id: str, now: int,
                      body: bytes = b'{"id": 1}',
                      session: str = EXPECTED_SESSION) -> bytes:
    pop = signer.make_pop(
        token=token, verifier_id=verifier_id,
        resource="payments", action="read", body=body,
        channel_binding=ch.binding, now=now,
    )
    meta = encode_ok_doc({"resource": "payments", "action": "read",
                          "session_id": session,          # ← was EXPECTED_SESSION
                          "task": EXPECTED_TASK})
    return await ch._raw_invoke(pop, token, meta, body)

async def test_20_stolen_governor_key_attacker_cnf_rejected(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        attacker = cc.CapChainKey.generate(agent_id=client_node.spiffe_id)
        now = c.clock.now_seconds()
        forged = _forge(s, holder=client_node.spiffe_id, cnf=attacker.thumbprint,
                        tools={"payments:read", "payments:write", "payments:delete"},
                        budget=10**12, ttl=86400, now=now, audience=b.spiffe_id)
        async with c.handler(b.port, b.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await _invoke_raw(ch, token=forged, signer=attacker,
                                  verifier_id=b.spiffe_id, now=now)
            assert ei.value.code == "CNF_NOT_REGISTERED"
            
async def test_21_outsider_with_governor_identity_rejected(server_node, client_node, gateway_node):
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        outsider = Client(server_node, cfg)              # TLS identity = node-1
        now = outsider.clock.now_seconds()
        forged = _forge(s, holder=client_node.spiffe_id, cnf=outsider.key.thumbprint,
                        tools={"payments:read"}, budget=10**6, ttl=3600,
                        now=now, audience=b.spiffe_id)
        async with outsider.handler(b.port, b.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await _invoke_raw(ch, token=forged, signer=outsider.key,
                                  verifier_id=b.spiffe_id, now=now)
            assert ei.value.code == "ROLE_REQUIRED"

@pytest.mark.parametrize("tools,budget,ttl,code", [
    ({"payments:read", "payments:delete"}, 1_000_000, 3600, "SCOPE_EXCEEDS_ENTITLEMENT"),
    ({"*"},                                1_000_000, 3600, "SCOPE_EXCEEDS_ENTITLEMENT"),
    ({"payments:read"},                    10**12,    3600, "BUDGET_EXCEEDS_ENTITLEMENT"),
    ({"payments:read"},                    1_000_000, 86400, "TTL_EXCEEDS_ENTITLEMENT"),
])
async def test_22_registered_holder_overbroad_token_rejected(
        server_node, client_node, gateway_node, tools, budget, ttl, code):
    """The cnf is registered, so only the ceiling is under test."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        now = c.clock.now_seconds()
        forged = _forge(s, holder=client_node.spiffe_id, cnf=c.key.thumbprint,
                        tools=tools, budget=budget, ttl=ttl,
                        now=now, audience=b.spiffe_id)
        async with c.handler(b.port, b.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await _invoke_raw(ch, token=forged, signer=c.key,
                                  verifier_id=b.spiffe_id, now=now)
            assert ei.value.code == code


async def test_23_legit_token_with_other_pop_key_rejected(server_node, client_node, gateway_node):
    """Tests capchain, not the new code. If this fails, the gateway is not
    binding PoP to leaf.cnf, which is a hole regardless of the table."""
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        async with c.handler(s.port, s.name, cfg) as ch:
            await ch.enroll()
            cap = await ch.request_token("payments:read")

        attacker = cc.CapChainKey.generate(agent_id=client_node.spiffe_id)
        async with c.handler(b.port, b.name, cfg) as ch:
            with pytest.raises(RemoteError) as ei:
                await _invoke_raw(ch, token=cap.raw, signer=attacker,
                                  verifier_id=b.spiffe_id, now=c.clock.now_seconds())
            assert ei.value.code == "POP_MISMATCH"


async def test_24_many_tokens_cannot_exceed_outstanding_budget(server_node, client_node, gateway_node):
    """The hole in my previous version.

    The attacker holds the governor key and forges N tokens with N *different*
    session_ids. Each token gets a distinct cid → distinct jti → distinct
    digest, so ``derive_cid`` cannot dedup them. The only remaining defense
    is ``max_outstanding_budget_micros`` on the entitlement row (3M). With
    each token claiming 1M, the fourth must be rejected.
    """
    cfg = TransportConfig(stream_window=4 * 1024)
    async with transport_pair(server_node, client_node, gateway_node) as (b, s, c):
        now = c.clock.now_seconds()
        codes = []

        async with c.handler(b.port, b.name, cfg) as ch:
            for i in range(4):
                sess = f"session-{i}"
                tok = _forge(
                    s, holder=client_node.spiffe_id, cnf=c.key.thumbprint,
                    tools={"payments:read"}, budget=1_000_000, ttl=3600,
                    now=now, audience=b.spiffe_id, session=sess,
                )
                try:
                    await _invoke_raw(
                        ch, token=tok, signer=c.key,
                        verifier_id=b.spiffe_id, now=now, session=sess,
                    )
                    codes.append("OK")
                except RemoteError as exc:
                    codes.append(exc.code)

        assert codes == ["OK", "OK", "OK", "OUTSTANDING_BUDGET_EXCEEDED"]



async def test_25_admit_unit():
    row = cc.Entitlement(cnf=frozenset({"k"}), tools=frozenset({"t"}), audience=frozenset({"a"}),
                      max_budget_micros=100, max_ttl_seconds=60,
                      max_outstanding_budget_micros=150, max_live_tokens=2)
    t = cc.EntitlementTable({("i", "h"): row})

    def chk(d, j, budget, exp=1000):
        return cc.Checked(key=("i", "h"), digest=d, jti=j, budget=budget, exp=exp, row=row)

    def code(c, now=0):
        with pytest.raises(cc.EntitlementError) as ei:
            t.admit(c, now=now)
        return ei.value.code

    t.admit(chk("d1", "j1", 100), now=0)
    t.admit(chk("d1", "j1", 100), now=0)                          # same token: idempotent
    assert code(chk("d2", "j1", 100)) == "JTI_CONFLICT"           # same jti, different bytes
    assert code(chk("d3", "j3", 100)) == "OUTSTANDING_BUDGET_EXCEEDED"
    t.admit(chk("d4", "j4", 50), now=0)                           # exactly 150
    assert code(chk("d5", "j5", 0)) == "TOO_MANY_LIVE_TOKENS"
    t.admit(chk("d6", "j6", 100, exp=5000), now=2000)             # earlier tokens expired



