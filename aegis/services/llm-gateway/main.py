from __future__ import annotations
from dataclasses import dataclass
import struct

import asyncio
import hashlib
import json
import logging
import ssl
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Iterable, Protocol, Sequence

from libs.transport.stream_session import Stream, TransportConfig, TransportError
from libs.transport.tls import TlsConnection


from libs.agentid import (
    bootstrap, 
    Bootstrap, 
    IdentitySnapshot, 
    SSLContextHolder, 
    SVIDMaterial, 
    SVIDWatcher, 
    IdentityService, 
    IdentityError
)
log = logging.getLogger("aegis.node")

def line(tag: str, snap: IdentitySnapshot) -> None:
    now = datetime.now(timezone.utc).strftime("%H:%M:%S")
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
        await asyncio.Event().wait()          # run forever
    finally:
        await boot.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
