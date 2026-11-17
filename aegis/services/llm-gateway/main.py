from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from libs.agentid import (
    IdentitySnapshot,
    bootstrap,
)

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


async def handler():

    boot = await bootstrap(watch=True)
    line("initial", boot.identity.current)

    async def on_rotate(snap: IdentitySnapshot) -> None:
        line("ROTATE", snap)

    def on(s):
        asyncio.create_task(on_rotate(s))

    boot.identity.subscribe(on)


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
