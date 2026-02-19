"""
Async Graph API client with pagination, throttling, retry, and safety enforcement.
Designed for large tenants (10k–250k users) with memory-safe streaming.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, AsyncGenerator, Optional

import httpx

from ..config import (
    GRAPH_BASE_URL,
    GRAPH_API_VERSION,
    GRAPH_BETA_VERSION,
    MAX_RETRIES,
    INITIAL_BACKOFF_SECONDS,
    MAX_BACKOFF_SECONDS,
    BACKOFF_MULTIPLIER,
    DEFAULT_PAGE_SIZE,
    MAX_PAGES_PER_ENDPOINT,
    BATCH_SIZE,
    MAX_CONCURRENT_REQUESTS,
)
from ..safety.guardian import SafetyGuardian, SafetyViolation

logger = logging.getLogger("m365_security_engine.graph")


class GraphAPIError(Exception):
    """Raised when Graph API returns a non-recoverable error."""
    def __init__(self, status_code: int, message: str, url: str):
        self.status_code = status_code
        self.url = url
        super().__init__(f"Graph API Error {status_code} for {url}: {message}")


class GraphClient:
    """
    Async Microsoft Graph API client.
    Features:
      - Safety-validated requests (read-only enforcement)
      - Automatic pagination with @odata.nextLink
      - Exponential backoff on 429/503/504
      - Concurrent request semaphore
      - Streaming generators for large result sets
      - v1.0 and beta endpoint support
    """

    def __init__(self, access_token: str, guardian: SafetyGuardian):
        self.access_token = access_token
        self.guardian = guardian
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self._request_count = 0
        self._throttle_count = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=30.0),
            limits=httpx.Limits(
                max_connections=MAX_CONCURRENT_REQUESTS * 2,
                max_keepalive_connections=MAX_CONCURRENT_REQUESTS,
            ),
            headers={
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "ConsistencyLevel": "eventual",  # Required for $count, $search
            },
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    def _build_url(self, endpoint: str, beta: bool = False) -> str:
        """Build full Graph URL from relative endpoint."""
        if endpoint.startswith("http"):
            return endpoint
        version = GRAPH_BETA_VERSION if beta else GRAPH_API_VERSION
        endpoint = endpoint.lstrip("/")
        return f"{GRAPH_BASE_URL}/{version}/{endpoint}"

    async def get(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        beta: bool = False,
    ) -> dict:
        """
        Execute a single GET request with retry/throttle handling.
        """
        url = self._build_url(endpoint, beta=beta)
        self.guardian.validate_request("GET", url)

        async with self._semaphore:
            return await self._execute_with_retry("GET", url, params=params)

    async def get_all_pages(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        beta: bool = False,
        top: Optional[int] = None,
        skip_top: bool = False,
    ) -> list[dict]:
        """
        Fetch all pages of a paginated endpoint into a list.
        Use get_all_pages_stream() for very large datasets.
        Set skip_top=True for endpoints that don't support $top.
        """
        items = []
        async for item in self.get_all_pages_stream(endpoint, params, beta, top, skip_top=skip_top):
            items.append(item)
        return items

    async def get_all_pages_stream(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        beta: bool = False,
        top: Optional[int] = None,
        skip_top: bool = False,
    ) -> AsyncGenerator[dict, None]:
        """
        Stream all pages of a paginated endpoint as an async generator.
        Memory-safe for large tenants — yields one item at a time.
        Set skip_top=True for endpoints that don't support $top.
        """
        if params is None:
            params = {}
        if not skip_top:
            if top and "$top" not in params:
                params["$top"] = str(min(top, DEFAULT_PAGE_SIZE))
            elif "$top" not in params:
                params["$top"] = str(DEFAULT_PAGE_SIZE)

        url = self._build_url(endpoint, beta=beta)
        pages = 0

        while url and pages < MAX_PAGES_PER_ENDPOINT:
            self.guardian.validate_request("GET", url)

            async with self._semaphore:
                data = await self._execute_with_retry("GET", url, params=params)

            # Surface 403 Forbidden instead of silently returning empty
            if data.get("_forbidden"):
                raise GraphAPIError(
                    403,
                    data.get("_error_message", "Forbidden — missing API permission"),
                    url,
                )

            for item in data.get("value", []):
                yield item

            # Follow nextLink for pagination
            url = data.get("@odata.nextLink")
            params = None  # nextLink contains all params
            pages += 1

        if pages >= MAX_PAGES_PER_ENDPOINT:
            logger.warning(
                f"Pagination safety cap reached ({MAX_PAGES_PER_ENDPOINT} pages) "
                f"for endpoint: {endpoint}"
            )

    async def get_count(self, endpoint: str, beta: bool = False) -> int:
        """Get $count for an endpoint (requires ConsistencyLevel: eventual)."""
        url = self._build_url(endpoint, beta=beta)
        count_url = f"{url}/$count"
        self.guardian.validate_request("GET", count_url)

        async with self._semaphore:
            response = await self._execute_raw("GET", count_url)
            try:
                return int(response.text.strip())
            except (ValueError, AttributeError):
                return -1

    async def batch_get(
        self,
        endpoints: list[str],
        beta: bool = False,
    ) -> list[dict]:
        """
        Execute multiple GET requests as a Graph $batch.
        Splits into chunks of BATCH_SIZE (max 20).
        """
        results = []
        for i in range(0, len(endpoints), BATCH_SIZE):
            chunk = endpoints[i:i + BATCH_SIZE]
            batch_body = {
                "requests": [
                    {
                        "id": str(idx),
                        "method": "GET",
                        "url": ep if ep.startswith("/") else f"/{ep}",
                    }
                    for idx, ep in enumerate(chunk)
                ]
            }
            version = GRAPH_BETA_VERSION if beta else GRAPH_API_VERSION
            batch_url = f"{GRAPH_BASE_URL}/{version}/$batch"

            # Batch uses POST but is on the safe list
            self.guardian.validate_request("POST", batch_url, batch_body)

            async with self._semaphore:
                data = await self._execute_with_retry(
                    "POST", batch_url, json_body=batch_body
                )

            for resp in data.get("responses", []):
                if resp.get("status") == 200:
                    results.append(resp.get("body", {}))
                else:
                    status = resp.get("status")
                    msg = resp.get("body", {}).get("error", {}).get("message", "Unknown")
                    # 403s are expected permission gaps handled by the caller;
                    # log at DEBUG to avoid noisy output.
                    if status == 403:
                        logger.debug(
                            f"Batch sub-request {resp.get('id')} permission denied (403): {msg}"
                        )
                    else:
                        logger.warning(
                            f"Batch sub-request {resp.get('id')} failed: {status} — {msg}"
                        )
                    results.append({"_error": True, "status": status, "_error_message": msg})

        return results

    async def _execute_with_retry(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        json_body: Optional[dict] = None,
    ) -> dict:
        """Execute request with exponential backoff on throttling."""
        backoff = INITIAL_BACKOFF_SECONDS

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = await self._execute_raw(
                    method, url, params=params, json_body=json_body
                )
                self._request_count += 1

                if response.status_code == 200:
                    if not response.content or not response.content.strip():
                        # Some endpoints (e.g. WIP policies on tenants that
                        # don't use WIP) return HTTP 200 with an empty body.
                        return {"value": []}
                    try:
                        return response.json()
                    except Exception:
                        logger.debug(f"200 response with non-JSON body from {url}")
                        return {"value": []}

                if response.status_code == 204:
                    return {}

                if response.status_code == 404:
                    logger.debug(f"404 Not Found: {url}")
                    return {"value": [], "_not_found": True}

                if response.status_code in (429, 503, 504):
                    self._throttle_count += 1
                    retry_after = float(
                        response.headers.get("Retry-After", backoff)
                    )
                    wait_time = max(retry_after, backoff)
                    logger.warning(
                        f"Throttled ({response.status_code}) on {url}. "
                        f"Retry {attempt + 1}/{MAX_RETRIES} in {wait_time:.1f}s"
                    )
                    await asyncio.sleep(wait_time)
                    backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_SECONDS)
                    continue

                if response.status_code == 403:
                    error_body = response.json() if response.content else {}
                    error_msg = error_body.get("error", {}).get("message", "Forbidden")
                    logger.warning(f"403 Forbidden: {url} — {error_msg}")
                    return {"value": [], "_forbidden": True, "_error_message": error_msg}

                # Other errors
                error_body = response.json() if response.content else {}
                error_msg = error_body.get("error", {}).get("message", response.text[:200])
                raise GraphAPIError(response.status_code, error_msg, url)

            except httpx.TimeoutException:
                logger.warning(f"Timeout on {url}, attempt {attempt + 1}/{MAX_RETRIES}")
                if attempt == MAX_RETRIES:
                    raise
                await asyncio.sleep(backoff)
                backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_SECONDS)

            except httpx.ConnectError as e:
                logger.warning(f"Connection error on {url}: {e}")
                if attempt == MAX_RETRIES:
                    raise
                await asyncio.sleep(backoff)
                backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF_SECONDS)

        return {"value": [], "_max_retries_exceeded": True}

    async def _execute_raw(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        json_body: Optional[dict] = None,
    ) -> httpx.Response:
        """Execute raw HTTP request."""
        if not self._client:
            raise RuntimeError("GraphClient not initialized. Use 'async with' context.")

        if method == "GET":
            return await self._client.get(url, params=params)
        elif method == "POST":
            return await self._client.post(url, json=json_body, params=params)
        else:
            raise SafetyViolation(f"Unsupported method at raw level: {method}")

    def get_stats(self) -> dict:
        """Return client statistics."""
        return {
            "total_requests": self._request_count,
            "throttle_events": self._throttle_count,
        }
