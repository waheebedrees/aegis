from __future__ import annotations
import contextlib
import logging
from typing import Awaitable, Callable, Protocol, TypeVar, Any, AsyncGenerator
from dataclasses import dataclass
import inspect
import asyncio
from contextlib import asynccontextmanager
from collections.abc import Iterable
import uuid
import time
import hashlib
import os
import time

from  libs.capchain.checkpoint import (
    BudgetLedger,
    migrate,
    Evidence,
    RevocationStore,
    ReplayStore,
    EvidenceStore,
    InMemoryBudgetLedger,
    InMemoryEvidenceLog,
    ReservationState,
    InMemoryReplayStore,
    InMemoryRevocationStore,
    SpendHandle,

)
import libs.capchain.capchain as cc 
log = logging.getLogger(__name__)


def _now(clock: Callable[[], int], override: int | None) -> int:
    if override is None:
        return clock()
    if type(override) is not int or override < 0:
        raise ValueError("now must be a non-negative integer timestamp")
    return override

@dataclass(frozen=True, slots=True)
class Policy:
    """Which roots are trusted and which delegation edges are permitted."""

    root_issuers: frozenset[str]
    edges: frozenset[tuple[str, str]]
    max_depth: int = 4

    def __post_init__(self) -> None:
        roots = frozenset(self.root_issuers)
        if not roots or any(not isinstance(r, str) or not r for r in roots):
            raise ValueError("root_issuers must be non-empty strings")
        object.__setattr__(self, "root_issuers", roots)

        normalized: set[tuple[str, str]] = set()
        for edge in self.edges:
            pair = tuple(edge)
            if len(pair) != 2 or any(not isinstance(p, str) or not p for p in pair):
                raise ValueError("each edge must be a pair of non-empty strings")
            normalized.add((pair[0], pair[1]))
        object.__setattr__(self, "edges", frozenset(normalized))

        if type(self.max_depth) is not int or self.max_depth < 0:
            raise ValueError("max_depth must be a non-negative int")

    def allows_root(self, issuer: str) -> bool:
        return issuer in self.root_issuers

    def allows_edge(self, issuer: str, delegate: str) -> bool:
        return (issuer, delegate) in self.edges


@dataclass(frozen=True, slots=True)
class ServerContext:
    """Facts the server already knows, independent of the request payload.

    Populate from your own session store and routing table. Taking any of
    these from a header, body field, or query parameter removes the
    protection they provide.
    """

    session_id: str
    task: str
    domain: str = ""

    def __post_init__(self) -> None:
        if not cc.bounded_str(self.session_id, cc.MAX_SESSION_ID_CHARS):
            raise ValueError("session_id")
        if not cc.bounded_str(self.task, cc.MAX_TASK_CHARS):
            raise ValueError("task")
        if not isinstance(self.domain, str) or len(self.domain) > 512:
            raise ValueError("domain")

@dataclass(frozen=True, slots=True)
class Call:
    """The operation being authorized. `tool` is "resource:action"."""

    resource: str
    action: str
    body: bytes

    def __post_init__(self) -> None:
        if not cc.bounded_str(self.resource, 128):
            raise ValueError("resource")
        if not cc.bounded_str(self.action, 128):
            raise ValueError("action")
        if not isinstance(self.body, (bytes, bytearray)):
            raise ValueError("body must be bytes")
        # Normalize to bytes: the field claims bytes, and frozen=True
        # does not prevent mutation of a bytearray in place.
        object.__setattr__(self, "body", bytes(self.body))

    @property
    def tool(self) -> str:
        return f"{self.resource}:{self.action}"



CostModel = Callable[[Call, ServerContext, cc.Verdict], int]

T = TypeVar("T")

class Permit:
    """An authorized call and its spend lifecycle.

    Call `mark_dispatched()` immediately before the side effect, then
    `settle(actual)`. Call `cancel()` only if nothing was dispatched.
    A reservation is refunded if, and only if, the block raises while
    still reserved or `cancel()` is called.
    """

    __slots__ = (
        "_clock",
        "_cost",
        "_evidence",
        "_ledger",
        "_record",
        "_spend",
        "_verdict",
    )

    def __init__(
        self,
        *,
        verdict: cc.Verdict,
        spend: SpendHandle,
        ledger:BudgetLedger,
        evidence: EvidenceStore,
        record: Evidence,
        clock: Callable[[], int],
    ) -> None:
        self._verdict = verdict
        self._spend = spend
        self._ledger = ledger
        self._evidence = evidence
        self._record = record
        self._clock = clock
        self._cost = spend.amount

    @property
    def chain_id(self) -> str:
        return self._verdict.cid

    @property
    def holder(self) -> str:
        return self._verdict.holder

    @property
    def issuer(self) -> str:
        return self._verdict.issuer

    @property
    def delegation_path(self) -> tuple[str, ...]:
        return self._verdict.path

    @property
    def scope(self) -> cc.Scope:
        return self._verdict.scope

    @property
    def cost_micros(self) -> int:
        return self._cost

    @property
    def evidence(self) -> Evidence:
        return self._record

    async def mark_dispatched(self) -> None:
        await self._ledger.mark_dispatched(self._spend)

    async def cancel(self) -> None:
        if self._spend.state != ReservationState.RESERVED:
            raise cc.RejectError(
                cc.Code.INTERNAL,
                f"cancel from {self._spend.state}",
            )
        await self._ledger.refund(self._spend)

    async def settle(self, actual_micros: int) -> None:
        """Record the real cost for a dispatched call.

        Ordering is deliberate: the SETTLED evidence record is written
        first, then the ledger is settled. Evidence is the source of truth
        for reconciliation.

        If the evidence append fails, the ledger is untouched and no charge
        adjustment happens. The call raises EVIDENCE_BROKEN; the reservation
        stands at the reserved amount (the tool was dispatched, so the
        charge is real) and no SETTLED record exists.

        If evidence succeeds but ledger.settle fails (for example
        BUDGET_EXHAUSTED on an overrun), the SETTLED record is already in
        the log with cost_micros=actual and related_id linking to the
        admission record. The exception propagates so the caller knows the
        ledger is inconsistent; the operator reconciles the ledger against
        the evidence log out of band.

        The previous ordering (ledger first, evidence second) left a
        settled budget with no SETTLED record and no join key from
        admission to settlement, which could not be reconciled from the
        ledger alone.
        """
        if self._spend.state != ReservationState.DISPATCHED:
            raise cc.RejectError(
                cc.Code.INTERNAL,
                f"settle from {self._spend.state}; call mark_dispatched first",
            )
        if not cc.is_int(actual_micros) or actual_micros < 0:
            raise cc.RejectError(
                cc.Code.INTERNAL,
                "actual_micros must be a non-negative int",
            )

        try:
            await self._evidence.append(
                {
                    "action_id": uuid.uuid4().hex,
                    "code": cc.Code.SETTLED,
                    "cid": self._verdict.cid,
                    "jtis": self._verdict.jtis,
                    "peer_id": self._record.peer_id,
                    "issuer": self._verdict.issuer,
                    "holder": self._verdict.holder,
                    "action": self._record.action,
                    "resource": self._record.resource,
                    "payload_hash": self._record.payload_hash,
                    "cost_micros": actual_micros,
                    "ts": self._clock(),
                    "pop_thumbprint": self._record.pop_thumbprint,
                    "channel_bound": self._record.channel_bound,
                    "verifier": self._record.verifier,
                    "related_id": self._record.action_id,
                }
            )
        except Exception as exc:
            raise cc.RejectError(
                cc.Code.EVIDENCE_BROKEN,
                f"settle evidence: {type(exc).__name__}",
            ) from exc

        # Evidence committed. From here on the cost is actual: the tool ran
        # and produced a result at this cost, regardless of whether the
        # ledger accepts the settlement. If ledger.settle raises, the
        # SETTLED record is authoritative and the ledger is reconciled
        # against it.
        self._cost = actual_micros
        await self._ledger.settle(self._spend, actual_micros)

    @property
    def state(self) -> str:
        return self._spend.state

    @property
    def reservation_micros(self) -> int:
        """Amount reserved at admission. Equals cost_micros until settle()."""
        return self._record.cost_micros

    async def execute(
        self,
        fn: Callable[[], T],
        *,
        settle: Callable[[T], int],
    ) -> T:
        """Mark dispatched, run `fn`, then settle with `settle(result)`.

        If `fn` raises, the reservation remains DISPATCHED. The enclosing
        `authorize` context manager commits the reservation on exception,
        because the side effect may have partially happened. Reconcile
        out of band if the cost differs.
        """
        await self.mark_dispatched()
        if inspect.iscoroutine(fn):
            result = await fn ()
        else:
            result = await asyncio.to_thread(fn)
        await self.settle(settle(result))
        return result



@dataclass(frozen=True, slots=True)
class GatewayConfig:
    agent_id: str
    roots: cc.TrustedRoots
    policy: Policy
    allowed_models: Iterable[str] = cc.MODELS
    ledger: BudgetLedger = InMemoryBudgetLedger()
    replay: ReplayStore  = InMemoryReplayStore()
    revocation: RevocationStore = InMemoryRevocationStore()
    evidence: EvidenceStore = InMemoryEvidenceLog()
    pop_max_skew: int = 30
    chain_max_skew: int | None = None
    domain_required_tools: Iterable[str] = ()
    clock: Callable[[], int] = lambda: int(time.time())
    cost_model: CostModel | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.roots, cc.TrustedRoots):
            raise TypeError("roots must be a TrustedRoots")
        if not isinstance(self.policy, Policy):
            raise TypeError("policy must be a Policy")
        if self.cost_model is not None and not callable(self.cost_model):
            raise TypeError("cost_model must be callable")
        if not isinstance(self.agent_id, str) or not self.agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if type(self.pop_max_skew) is not int or self.pop_max_skew < 0:
            raise ValueError("pop_max_skew must be a non-negative int")
        if isinstance(self.allowed_models, (str, bytes)):
            raise ValueError("allowed_models must be an iterable, not a string")
        if isinstance(self.domain_required_tools, (str, bytes)):
            raise ValueError("domain_required_tools must be an iterable, not a string")
        if self.replay.ttl_seconds <= 2 * self.pop_max_skew:
            raise ValueError("replay TTL must exceed 2 * pop_max_skew")

        
class Gateway:
    """Authorizes requests presented over mTLS against a capability chain."""

    def __init__(
        self,
        cfg:GatewayConfig,
    ) -> None:
        if not isinstance(cfg, GatewayConfig):
            raise ValueError("unkown config type")

        self._cfg = cfg
        self.agent_id = self._cfg.agent_id
        self._roots = self._cfg.roots
        self._policy =  self._cfg.policy
        self._allowed_models = self._cfg.allowed_models
        self._skew =  self._cfg.pop_max_skew
        self._domain_required =  self._cfg.domain_required_tools
        self._clock =  self._cfg.clock
        self._cost_model =  self._cfg.cost_model
        self._chain_skew =  (
            self._cfg.chain_max_skew 
            if  self._cfg.chain_max_skew is not None
             else  self._cfg.pop_max_skew
        )
        self._ledger = self._cfg.ledger
        self._replay = self._cfg.replay 
        self._evidence = self._cfg.evidence 
        self._revocation = self._cfg.revocation

    @property
    def evidence(self) -> EvidenceStore:
        return self._evidence
    @property
    def replay(self) -> ReplayStore:
        return self.replay
    
    @property
    def revocation(self) -> RevocationStore:
        return self._revocation

    @property
    def policy(self) -> Policy:
        """Public read access; replaces external reads of _policy."""
        return self._policy

    @asynccontextmanager
    async def authorize(
        self,
        *,
        peer_id:str ,
        token: bytes,
        channel_binding: bytes,
        call: Call,
        context: ServerContext,
        proof: bytes | None = None,
        cost_model: CostModel | None = None,
    ) -> AsyncGenerator[Permit]:
        """Authorize one call, reserving budget for its duration.

        The reservation is `cost_model(call, context, verdict)`. It must return
        an upper bound on the real cost; settlement cannot claw back a side
        effect that already happened.
        """
        now = self._clock()
        try:
            permit = await self._admit(
                channel_binding=channel_binding,
                peer_id=peer_id,
                token=token,
                proof=proof,
                call=call,
                context=context,
                cost_model=cost_model,
                now=now,
            )

        except cc.RejectError as exc:
            try:
                await self._record_denial(exc, peer_id, call, now)
            except Exception:
                # The denial is the security decision; the recording failure is an
                # operational problem. Log it and let the caller see the actual
                # rejection, not EVIDENCE_BROKEN. (Contrast: _admit step 6 refuses
                # admission when evidence fails, because admission hasn't happened
                # until evidence exists.)
                log.exception(
                    "evidence store failed while recording denial %s; the denial itself stands",
                    exc.code,
                )
            raise
        except Exception as exc:
            rejection = cc.error(cc.Code.INTERNAL, type(exc).__name__)
            try:
                await self._record_denial(rejection, peer_id, call, now)
            except Exception:
                log.exception(
                    "evidence store failed while recording denial %s; the denial itself stands",
                    rejection.code,
                )
            raise rejection from exc

        spend = permit._spend
        try:
            yield permit
        except BaseException:
            if spend.state == ReservationState.RESERVED:
                try:
                    await self._ledger.refund(spend)
                except Exception as exc:
                    # The body's exception is what the caller cares about; the
                    # refund failure is an operational problem. Attach it to the
                    # rejection so both are visible, but surface STATE_UNAVAILABLE
                    # with the original body exception as __context__ — Python
                    # sets __context__ automatically when raising inside `except`.
                    raise cc.error(
                        cc.Code.STATE_UNAVAILABLE,
                        f"refund: {type(exc).__name__}",
                    ) from exc
            elif spend.state != ReservationState.CANCELLED:
                try:
                    await self._ledger.commit(spend)
                except Exception as exc:
                    raise cc.error(
                        cc.Code.STATE_UNAVAILABLE,
                        f"commit: {type(exc).__name__}",
                    ) from exc
            raise
        else:
            if spend.state == ReservationState.CANCELLED:
                return
            if spend.state == ReservationState.RESERVED:
                try:
                    await self._ledger.refund(spend)
                except Exception as exc:
                    # The body's exception is what the caller cares about; the
                    # refund failure is an operational problem. Attach it to the
                    # rejection so both are visible, but surface STATE_UNAVAILABLE
                    # with the original body exception as __context__ — Python
                    # sets __context__ automatically when raising inside `except`.
                    raise cc.error(
                        cc.Code.STATE_UNAVAILABLE,
                        f"refund: {type(exc).__name__}",
                    ) from exc

                return
            try:
                await self._ledger.commit(spend)
            except Exception as exc:
                raise cc.error(
                    cc.Code.STATE_UNAVAILABLE,
                    f"commit: {type(exc).__name__}",
                ) from exc

            if spend.state == ReservationState.DISPATCHED:
                raise cc.error(
                    cc.Code.INTERNAL,
                    "authorize exited with a dispatched, unsettled permit; "
                    "reservation committed at the reserved amount",
                )


    async def _admit(
        self,
        *,
        channel_binding: bytes,
        peer_id: str,
        token: bytes,
        proof: bytes | None,
        call: Call,
        context: ServerContext,
        cost_model: CostModel | None,
        now: int,
    ) -> Permit:
        if not isinstance(call, Call):
            raise cc.error(
                cc.Code.INTERNAL,
                "call must be a Call",
            )
        if not isinstance(context, ServerContext):
            raise cc.error(
                cc.Code.INTERNAL,
                "context must be a ServerContext",
            )

        # 1. Cryptographic chain.
        verdict = cc.verify_chain(
            token,
            roots=self._roots,
            now=now,
            max_depth=self._policy.max_depth,
            skew=self._chain_skew,
        )

        if verdict.model not in self._allowed_models:
            raise cc.error(
                cc.Code.POLICY_DENIED,
                f"model {verdict.model!r}",
            )

        key_bound = verdict.model == cc.Model.KEY_BOUND
        if key_bound:
            if proof is None:
                raise cc.error(
                    cc.Code.POP_REQUIRED,
                    "proof of possession required",
                )
            nonce = cc.verify_pop(
                cc.Signed.decode(proof),
                cnf=verdict.cnf,
                verifier_id=self.agent_id,
                token=bytes(token),
                resource=call.resource,
                action=call.action,
                body=bytes(call.body),
                channel_binding=channel_binding,
                now=now,
                max_skew=self._skew,
            )
            try:
                fresh = await self._replay.consume(
                    (
                        "pop-v2",
                        self.agent_id,
                        verdict.cnf,
                        nonce,
                    ),
                    now,
                )
            except Exception as exc:
                raise cc.error(
                    cc.Code.STATE_UNAVAILABLE,
                    f"replay store: {type(exc).__name__}",
                ) from exc
            if not fresh:
                raise cc.error(
                    cc.Code.REPLAY,
                    "nonce already used",
                )
        elif proof is not None:
            raise cc.error(
                cc.Code.MODEL_MISMATCH,
                "proof supplied for peer-bound token",
            )

        # 2. Presenter, audience, delegation policy.
        if peer_id != verdict.holder:
            raise cc.error(
                cc.Code.WRONG_HOLDER,
                f"peer {peer_id} != holder {verdict.holder}",
            )
        if not verdict.scope.allows_verifier(self.agent_id):
            raise cc.error(cc.Code.WRONG_AUDIENCE, self.agent_id)
        if not self._policy.allows_root(verdict.issuer):
            raise cc.error(
                cc.Code.POLICY_DENIED,
                f"issuer {verdict.issuer}",
            )
        for source, target in zip(
            verdict.path,
            verdict.path[1:],
            strict=False,
        ):
            if not self._policy.allows_edge(source, target):
                raise cc.error(
                    cc.Code.POLICY_DENIED,
                    f"edge {source} -> {target}",
                )

        # 3. Request against scope and server-held context.
        if not verdict.scope.allows_tool(call.tool):
            raise cc.error(cc.Code.SCOPE_MISMATCH, call.tool)
        if context.domain:
            if not verdict.scope.allows_domain(context.domain):
                raise cc.error(
                    cc.Code.SCOPE_MISMATCH,
                    f"domain {context.domain}",
                )

        
        elif call.tool in self._domain_required:
            raise cc.error(
                cc.Code.SCOPE_MISMATCH,
                f"{call.tool} requires a domain",
            )
        if verdict.session_id != context.session_id:
            raise cc.error(
                cc.Code.WRONG_SESSION,
                "token session != server session",
            )
        if verdict.task != context.task:
            raise cc.error(
                cc.Code.WRONG_TASK,
                "token task != server task",
            )

        # 4. Cost model. Runs only after every pure identity/policy/scope
        #    check has passed, so an unauthenticated presenter cannot
        #    drive a pricing service or DB lookup.
        model = cost_model if cost_model is not None else self._cost_model
        if model is None:
            raise cc.error(
                cc.Code.INTERNAL,
                "no cost model configured",
            )
        try:
            reserve_micros = model(call, context, verdict)
        except cc.RejectError:
            raise
        except Exception as exc:
            raise cc.error(
                cc.Code.INTERNAL,
                f"cost model: {type(exc).__name__}",
            ) from exc
        if not cc.is_int(reserve_micros) or reserve_micros < 0:
            raise cc. error(
                cc.Code.INTERNAL,
                f"cost model returned {reserve_micros!r}",
            )

        # 5. Revocation and budget.
        if reserve_micros > verdict.scope.budget_micros:
            raise cc.error(
                cc.Code.BUDGET_EXHAUSTED,
                f"{reserve_micros} > leaf cap",
            )

        try:
            revoked = await  self._revocation.find_revoked(
                agents=verdict.path,
                kids=(
                    *verdict.kids,
                    verdict.cnf,
                ),
                cids=(verdict.cid,),
                jtis=verdict.jtis,
            )
        except Exception as exc:
            raise cc.error(
                cc.Code.STATE_UNAVAILABLE,
                f"revocation store: {type(exc).__name__}",
            ) from exc
        if revoked:
            raise cc.error(
                cc.Code.REVOKED,
                f"{revoked[0]}={revoked[1]}",
            )

        try:
            spend = await self._ledger.reserve(
                verdict.cid,
                verdict.root_scope.budget_micros,
                verdict.budget_path,
                reserve_micros,
                expires_at=verdict.expires_at,
                now=now,
            )
        except cc.RejectError:
            raise
        except Exception as exc:
            raise cc.error(
                cc.Code.STATE_UNAVAILABLE,
                f"ledger: {type(exc).__name__}",
            ) from exc
        if spend is None:
            raise cc.error(
                cc.Code.BUDGET_EXHAUSTED,
                f"chain {verdict.cid}",
            )

        # 6. Admission evidence.
        try:
            record =  await self._evidence.append(
                {
                    "action_id": uuid.uuid4().hex,
                    "code": cc.Code.OK,
                    "cid": verdict.cid,
                    "jtis": verdict.jtis,
                    "peer_id": peer_id,
                    "issuer": verdict.issuer,
                    "holder": verdict.holder,
                    "action": call.action,
                    "resource": call.resource,
                    "payload_hash": cc.sha256_tag(call.body),
                    "cost_micros": reserve_micros,
                    "ts": now,
                    "pop_thumbprint": verdict.cnf if key_bound else "",
                    "channel_bound": key_bound,
                    "verifier": self.agent_id,
                    "related_id": "",
                }
            )

        except Exception as exc:
            with contextlib.suppress(Exception):
                await self._ledger.refund(spend)
            raise cc.error(
                cc.Code.EVIDENCE_BROKEN,
                type(exc).__name__,
            ) from exc

        return Permit(
            verdict=verdict,
            spend=spend,
            ledger=self._ledger,
            evidence=self._evidence,
            record=record,
            clock=self._clock,
        )

    async def _record_denial(
        self,
        rejection: cc.RejectError,
        peer_id: str,
        call: Call,
        now: int,
    ) -> None:
        resource = getattr(call, "resource", "")
        action = getattr(call, "action", "")
        body = getattr(call, "body", None)
        try:
            await self._evidence.append(
                {
                    "action_id": uuid.uuid4().hex,
                    "code": rejection.code,
                    "cid": "",
                    "jtis": (),
                    "peer_id": peer_id,
                    "issuer": "",
                    "holder": "",
                    "action": str(action),
                    "resource": str(resource),
                    "payload_hash": cc.sha256_tag(bytes(body))
                    if isinstance(body, (bytes, bytearray))
                    else "",
                    "cost_micros": 0,
                    "ts": now,
                    "pop_thumbprint": "",
                    "channel_bound": False,
                    "verifier": self.agent_id,
                    "related_id": "",
                }
            )
        except Exception as exc:
            raise cc.error(
                cc.Code.EVIDENCE_BROKEN,
                f"deny {rejection.code} not recorded: {type(exc).__name__}",
            ) from rejection

    async def verify(
        self,
        *,
        token: bytes,
        now: int | None = None,
    ) -> cc.Verdict:
        """Verify the chain and return the verdict. No state, no PoP, no budget."""
        timestamp = _now(self._clock, now)
        verdict = cc.verify_chain(
            token,
            roots=self._roots,
            now=timestamp,
            max_depth=self._policy.max_depth,
            skew=self._chain_skew,
        )
        if verdict.model not in self._allowed_models:
            raise cc.error(
                cc.Code.POLICY_DENIED,
                f"model {verdict.model!r}",
            )
        if not self._policy.allows_root(verdict.issuer):
            raise cc.error(
                cc.Code.POLICY_DENIED,
                f"issuer {verdict.issuer}",
            )
        for source, target in zip(
            verdict.path,
            verdict.path[1:],
            strict=False,
        ):
            if not self._policy.allows_edge(source, target):
                raise cc.error(
                    cc.Code.POLICY_DENIED,
                    f"edge {source} -> {target}",
                )
        return verdict

