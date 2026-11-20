import asyncio
from collections.abc import Awaitable, Callable
from typing import Protocol

from redis.asyncio import Redis


class Pacer(Protocol):
    async def wait_turn(self) -> None: ...


class RedisPacer:
    """Espacia las llamadas a una API entre todos los workers según el límite del plan."""

    def __init__(
        self,
        redis: Redis,
        key: str,
        interval_seconds: float,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.redis = redis
        self.key = key
        self.interval_ms = max(int(interval_seconds * 1000), 1)
        self.sleep = sleep

    async def wait_turn(self) -> None:
        while True:
            if await self.redis.set(self.key, "1", px=self.interval_ms, nx=True):
                return
            remaining_ms = await self.redis.pttl(self.key)
            await self.sleep(max(remaining_ms, 20) / 1000)
