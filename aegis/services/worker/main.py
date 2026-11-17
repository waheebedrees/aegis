from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import UTC, datetime

from libs.agentid.identity import (
    IdentitySnapshot,
    bootstrap,
)
from libs.capchain.checkpoint import Stores, check_contract, migrate

log = logging.getLogger("aegis.node")


def line(tag: str, snap: IdentitySnapshot) -> None:
    now = datetime.now(UTC).strftime("%H:%M:%S")
    print(
        f"{now} {tag:<7} "
        f"cred={snap.credential_id[12:24]}… "
        f"bundle={snap.bundle_digest[7:19]}… "
        f"remain={snap.remain:6.1f}s",
        flush=True,
    )


async def selftest() -> int:
    failures = 0
    async with await Stores.open("memory") as stores:
        try:
            await check_contract(stores)
            print("  [ok]   memory")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] memory: {type(e).__name__}: {e}")

    url = "redis://:your_redis_password@redis:6379/0"
    url = os.environ["CAPCHAIN_REDIS_URL"]
    print(f"{os.environ['CAPCHAIN_REDIS_PREFIX']=}")
    print(f"{os.environ['CAPCHAIN_REDIS_URL']=}")

    if url:
        prefix = f"capchain:test:{uuid.uuid4().hex}"
        try:
            async with await Stores.open(
                "redis",
                redis_url=url,
                prefix=prefix,
                env="development",
            ) as stores:
                await check_contract(stores)
            print("  [ok]   redis")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] redis: {type(e).__name__}: {e}")
    dsn = os.environ.get("CAPCHAIN_TEST_POSTGRES")
    if dsn:
        schema = "capchain_test_" + uuid.uuid4().hex[:12]
        try:
            await migrate(dsn, schema)
            async with await Stores.open(
                "database",
                postgres_dsn=dsn,
                schema=schema,
                env="development",
            ) as stores:
                await check_contract(stores)
            print("  [ok]   database")
        except Exception as e:
            failures += 1
            print(f"  [FAIL] database: {type(e).__name__}: {e}")
    print(f"store selftest: {failures} failure(s)")
    return failures


async def main() -> None:
    boot = await bootstrap(watch=True)
    line("initial", boot.identity.current)

    async def on_rotate(snap: IdentitySnapshot) -> None:
        line("ROTATE", snap)

    def on(s):
        asyncio.create_task(on_rotate(s))

    boot.identity.subscribe(on)

    try:
        await asyncio.Event().wait()  # run forever
    finally:
        await boot.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
