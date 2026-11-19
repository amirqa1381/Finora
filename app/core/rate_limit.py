"""Fixed-window counters on Redis, used for login lockout and register limits."""

from redis.asyncio import Redis


class RateLimiter:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def hit(self, key: str, *, window_seconds: int) -> int:
        """Add one to the counter and return the new value.

        The first hit starts the window. INCR and EXPIRE go in one pipeline,
        so a crash between them cannot leave a key that never expires.
        """
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)  # nx: only if no TTL yet
            results = await pipe.execute()
        return int(results[0])

    async def count(self, key: str) -> int:
        value = await self._redis.get(key)
        return int(value) if value else 0

    async def retry_after(self, key: str, *, default: int) -> int:
        ttl = await self._redis.ttl(key)
        return ttl if ttl > 0 else default

    async def reset(self, key: str) -> None:
        await self._redis.delete(key)
