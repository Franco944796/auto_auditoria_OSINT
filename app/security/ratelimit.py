import hashlib
import time
from dataclasses import dataclass

from redis.asyncio import Redis


@dataclass(frozen=True, slots=True)
class Limit:
    count: int
    seconds: int


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("rate limit")
        self.retry_after = max(retry_after, 1)


def subject_key(value: str) -> str:
    """Las claves de Redis llevan un hash: ni emails ni IPs en claro."""
    return hashlib.sha256(value.encode()).hexdigest()[:32]


class RateLimiter:
    """Ventana fija en Redis: compartida entre procesos y workers."""

    def __init__(self, redis: Redis, prefix: str = "rl") -> None:
        self.redis = redis
        self.prefix = prefix

    async def hit(self, key: str, limit: Limit) -> None:
        now = int(time.time())
        window = now // limit.seconds
        redis_key = f"{self.prefix}:{key}:{limit.seconds}:{window}"
        count = await self.redis.incr(redis_key)
        if count == 1:
            await self.redis.expire(redis_key, limit.seconds)
        if count > limit.count:
            raise RateLimitExceeded(limit.seconds - now % limit.seconds)
