import asyncio

import pytest

import libs.capchain.capchain as cc
import libs.capchain.gateway as gw
from libs.capchain.checkpoint import (
    InMemoryReplayStore,
)

pytestmark = pytest.mark.asyncio


async def test_fixes():
    print("=== Testing Fix 1: Gateway.replay recursion ===")
    roots = cc.TrustedRoots(b"0" * 32, {"root": b"0" * 32})
    policy = gw.Policy(frozenset({"root"}), frozenset(), 1)
    cfg = gw.GatewayConfig(agent_id="test-gw", roots=roots, policy=policy)
    g = gw.Gateway(cfg)

    replay_store = g.replay
    assert replay_store is not None, "replay is None"
    assert isinstance(replay_store, InMemoryReplayStore)
    assert replay_store is g._replay
    print("[PASS] Gateway.replay successfully returns self._replay without RecursionError!")

    print("\n=== Testing Fix 2: GatewayConfig mutable defaults ===")
    cfg1 = gw.GatewayConfig(agent_id="gw1", roots=roots, policy=policy)
    cfg2 = gw.GatewayConfig(agent_id="gw2", roots=roots, policy=policy)

    assert cfg1.ledger is not cfg2.ledger, "Ledgers should be distinct instances"
    assert cfg1.replay is not cfg2.replay, "ReplayStores should be distinct instances"
    assert cfg1.revocation is not cfg2.revocation, "RevocationStores should be distinct instances"
    assert cfg1.evidence is not cfg2.evidence, "EvidenceLogs should be distinct instances"

    print("\n=== Testing Fix 3: Permit.execute async inspection ===")

    class MockPermit:
        def __init__(self):
            self.dispatched = False
            self.settled_cost = None

        async def mark_dispatched(self):
            self.dispatched = True

        async def settle(self, actual_micros: int):
            self.settled_cost = actual_micros

    execute_fn = gw.Permit.execute

    # 3a: async def function
    p_a = MockPermit()

    async def async_fn():
        return "async_fn_val"

    res_a = await execute_fn(p_a, async_fn, settle=lambda r: 100)
    assert res_a == "async_fn_val"
    assert p_a.dispatched and p_a.settled_cost == 100
    print("[PASS] 3a: async def function executed and awaited correctly")

    # 3b: coroutine object
    p_b = MockPermit()
    res_b = await execute_fn(p_b, async_fn(), settle=lambda r: 200)
    assert res_b == "async_fn_val"
    assert p_b.dispatched and p_b.settled_cost == 200
    print("[PASS] 3b: coroutine object awaited directly without calling ()")

    # 3c: lambda returning coroutine
    p_c = MockPermit()
    res_c = await execute_fn(p_c, lambda: async_fn(), settle=lambda r: 300)
    assert res_c == "async_fn_val"
    assert p_c.dispatched and p_c.settled_cost == 300
    print("[PASS] 3c: lambda returning coroutine handled correctly")

    # 3d: sync function
    p_d = MockPermit()

    def sync_fn():
        return "sync_fn_val"

    res_d = await execute_fn(p_d, sync_fn, settle=lambda r: 400)
    assert res_d == "sync_fn_val"
    assert p_d.dispatched and p_d.settled_cost == 400
    print("[PASS] 3d: sync function executed in worker thread correctly")

    # 3e: callable class with async __call__
    class AsyncCallable:
        async def __call__(self):
            return "async_callable_val"

    p_e = MockPermit()
    res_e = await execute_fn(p_e, AsyncCallable(), settle=lambda r: 500)
    assert res_e == "async_callable_val"
    assert p_e.dispatched and p_e.settled_cost == 500
    print("[PASS] 3e: callable object with async __call__ executed correctly")

    # 3f: async settle callback
    p_f = MockPermit()

    async def async_settle(res):
        return 600

    res_f = await execute_fn(p_f, sync_fn, settle=async_settle)
    assert res_f == "sync_fn_val"
    assert p_f.settled_cost == 600
    print("[PASS] 3f: async settle callback awaited correctly")

    print("\n>>> ALL 3 DEFECT FIXES VERIFIED AND PASSING! <<<")


if __name__ == "__main__":
    asyncio.run(test_fixes())
