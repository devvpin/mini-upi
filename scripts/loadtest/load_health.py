"""Small deployment smoke load test for the 200-user Phase 7 gate."""

from __future__ import annotations

import asyncio
import statistics
import sys
import time

import httpx


async def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost/health"

    async def request(client: httpx.AsyncClient) -> float:
        started = time.perf_counter()
        response = await client.get(url)
        response.raise_for_status()
        return (time.perf_counter() - started) * 1000

    async with httpx.AsyncClient(timeout=10) as client:
        latencies = await asyncio.gather(*(request(client) for _ in range(200)))
    p95 = statistics.quantiles(latencies, n=20)[18]
    print(f"requests=200 p95_ms={p95:.2f} mean_ms={statistics.mean(latencies):.2f}")


if __name__ == "__main__":
    asyncio.run(main())
