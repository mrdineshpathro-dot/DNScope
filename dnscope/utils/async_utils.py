"""Asyncio helpers with *bounded* concurrency.

DNScope never creates unbounded task fan-out: every helper here enforces an
explicit concurrency ceiling and, where relevant, a rate budget. That keeps
large scans predictable for both the local machine and the queried
infrastructure.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any, TypeVar

from dnscope.exceptions import LimitsExceeded
from dnscope.utils.logging import get_logger

T = TypeVar("T")
R = TypeVar("R")

_log = get_logger("async")

#: Absolute ceiling on concurrent tasks, independent of user configuration.
HARD_CONCURRENCY_CEILING = 256

#: Absolute ceiling on total tasks in a single gather operation.
HARD_TASK_CEILING = 100_000


def clamp(value: int, minimum: int, maximum: int) -> int:
    """Clamp ``value`` into ``[minimum, maximum]``."""
    return max(minimum, min(maximum, value))


def semaphore_from_limit(limit: int) -> asyncio.Semaphore:
    """Build a semaphore clamped to the hard concurrency ceiling."""
    return asyncio.Semaphore(clamp(int(limit), 1, HARD_CONCURRENCY_CEILING))


class RateLimiter:
    """Async token-bucket rate limiter.

    ``rate`` is the maximum sustained operations per second; ``burst`` allows a
    short initial spike. ``acquire`` waits when the budget is exhausted.
    """

    __slots__ = ("_burst", "_lock", "_rate", "_tokens", "_updated")

    def __init__(self, rate: float, *, burst: int | None = None) -> None:
        self._rate = max(0.0, float(rate))
        self._burst = float(burst if burst is not None else max(1, int(self._rate or 1)))
        self._tokens = self._burst
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def rate(self) -> float:
        """Configured operations per second (``0`` means unlimited)."""
        return self._rate

    async def acquire(self, tokens: float = 1.0) -> None:
        """Wait until ``tokens`` are available, then consume them."""
        if self._rate <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                await asyncio.sleep(deficit / self._rate)

    def try_acquire(self, tokens: float = 1.0) -> bool:
        """Non-blocking acquire; returns ``False`` when the budget is empty."""
        if self._rate <= 0:
            return True
        now = time.monotonic()
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False


class SyncRateLimiter:
    """Blocking rate limiter for the synchronous code paths."""

    __slots__ = ("_interval", "_lock", "_next_at")

    def __init__(self, rate: float) -> None:
        self._interval = 0.0 if rate <= 0 else 1.0 / float(rate)
        self._next_at = 0.0
        import threading

        self._lock = threading.Lock()

    def wait(self) -> None:
        """Sleep if necessary to respect the configured rate."""
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next_at)
            self._next_at = scheduled + self._interval
        delay = scheduled - now
        if delay > 0:
            time.sleep(delay)


class BoundedGatherer:
    """Run coroutines with bounded concurrency and a global task ceiling.

    Example::

        gatherer = BoundedGatherer(concurrency=8, rate=20)
        results = await gatherer.run([query(name) for name in names])

    Results preserve input order; exceptions are captured as
    :class:`GatherError` entries instead of aborting the batch.
    """

    def __init__(
        self,
        *,
        concurrency: int = 8,
        rate: float = 0.0,
        max_tasks: int = HARD_TASK_CEILING,
        name: str = "gather",
    ) -> None:
        self.concurrency = clamp(concurrency, 1, HARD_CONCURRENCY_CEILING)
        self.max_tasks = clamp(max_tasks, 1, HARD_TASK_CEILING)
        self.name = name
        self._semaphore = semaphore_from_limit(self.concurrency)
        self._limiter = RateLimiter(rate) if rate > 0 else None

    async def _guard(self, awaitable: Awaitable[R]) -> R:
        async with self._semaphore:
            if self._limiter is not None:
                await self._limiter.acquire()
            return await awaitable

    async def run(self, awaitables: Sequence[Awaitable[R]]) -> list[R | GatherError]:
        """Await ``awaitables`` concurrently, returning ordered results."""
        tasks = list(awaitables)
        if len(tasks) > self.max_tasks:
            for task in tasks:
                task.close()
            raise LimitsExceeded(
                f"{self.name}: {len(tasks)} tasks exceeds the limit of {self.max_tasks}",
                details={"requested": len(tasks), "limit": self.max_tasks},
            )
        results: list[R | GatherError] = await asyncio.gather(
            *(self._guard(task) for task in tasks),
            return_exceptions=True,
        )
        normalized: list[R | GatherError] = []
        for item in results:
            if isinstance(item, BaseException):
                normalized.append(GatherError(item))
            else:
                normalized.append(item)
        return normalized

    async def map(
        self,
        func: Callable[[T], Awaitable[R]],
        items: Iterable[T],
    ) -> list[R | GatherError]:
        """Apply ``func`` to each item with bounded concurrency."""
        return await self.run([func(item) for item in items])


class GatherError:
    """Wrapper for an exception raised by one task inside a batch."""

    __slots__ = ("error",)

    def __init__(self, error: BaseException) -> None:
        self.error = error

    @property
    def message(self) -> str:
        return str(self.error)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"GatherError({self.error!r})"


def run_async(coro: Awaitable[R], *, new_loop: bool = False) -> R:
    """Run a coroutine from synchronous CLI code.

    Handles the common ``asyncio.run() cannot be called from a running event
    loop`` case by spinning up a dedicated loop in a worker thread when one is
    already active (for example inside a notebook or the FastAPI test client).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]

    if new_loop:
        return _run_in_thread(coro)
    raise RuntimeError("an event loop is already running; pass new_loop=True")


def _run_in_thread(coro: Awaitable[R]) -> R:
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, coro)  # type: ignore[arg-type]
        return future.result()


def gather_with_limits(
    awaitables: Sequence[Awaitable[R]],
    *,
    concurrency: int,
    rate: float = 0.0,
    name: str = "gather",
) -> list[R | GatherError]:
    """Convenience wrapper around :class:`BoundedGatherer`."""
    return run_async(BoundedGatherer(concurrency=concurrency, rate=rate, name=name).run(awaitables))


def with_timeout(awaitable: Awaitable[R], timeout: float) -> Awaitable[R]:
    """Apply ``asyncio.timeout`` semantics to a coroutine."""

    async def _wrapped() -> R:
        return await asyncio.wait_for(awaitable, timeout=max(0.001, timeout))

    return _wrapped()


def as_completed_bounded(
    awaitables: Sequence[Awaitable[R]],
    *,
    concurrency: int,
    rate: float = 0.0,
) -> list[R | GatherError]:
    """Same as :func:`gather_with_limits` but tolerant of empty inputs."""
    if not awaitables:
        return []
    return gather_with_limits(awaitables, concurrency=concurrency, rate=rate)


class AsyncStopwatch:
    """Context manager measuring elapsed wall-clock time."""

    __slots__ = ("elapsed", "_start")

    def __init__(self) -> None:
        self.elapsed = 0.0
        self._start = 0.0

    def __enter__(self) -> "AsyncStopwatch":
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc: object) -> None:
        self.elapsed = time.monotonic() - self._start


def describe(value: Any) -> str:  # pragma: no cover - debug helper
    """Short debug description of a value."""
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."
