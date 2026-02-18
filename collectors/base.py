"""
Base collector class — Abstract interface for all data collectors.
Defines the contract for modular, parallelizable data collection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from ..graph.client import GraphClient, GraphAPIError
from ..cache.store import ScanCache
from ..config import CollectionConfig

logger = logging.getLogger("m365_security_engine.collectors")


class CollectorResult:
    """Standardized result from a collector."""

    def __init__(self, collector_name: str):
        self.collector_name = collector_name
        self.data: dict[str, Any] = {}
        self.metadata: dict[str, Any] = {
            "collector": collector_name,
            "started_at": None,
            "completed_at": None,
            "duration_seconds": 0,
            "items_collected": 0,
            "errors": [],
            "warnings": [],
            "endpoints_queried": 0,
            "skipped_sections": [],
        }

    def add_data(self, key: str, value: Any):
        self.data[key] = value
        if isinstance(value, list):
            self.metadata["items_collected"] += len(value)
        elif isinstance(value, dict):
            self.metadata["items_collected"] += 1

    def add_error(self, error: str):
        self.metadata["errors"].append(error)
        logger.error(f"[{self.collector_name}] {error}")

    def add_warning(self, warning: str):
        self.metadata["warnings"].append(warning)
        logger.warning(f"[{self.collector_name}] {warning}")

    def add_skipped(self, section: str, reason: str):
        self.metadata["skipped_sections"].append({"section": section, "reason": reason})
        logger.info(f"[{self.collector_name}] Skipped {section}: {reason}")

    def to_dict(self) -> dict:
        return {
            "data": self.data,
            "metadata": self.metadata,
        }


class BaseCollector(ABC):
    """
    Abstract base class for all collectors.

    Subclasses implement collect() to gather data from Graph API.
    The base class provides:
      - Caching integration
      - Timing and metadata
      - Error handling wrapper
      - Safe execution with fallback
    """

    name: str = "base"
    description: str = "Base collector"

    def __init__(
        self,
        graph: GraphClient,
        config: CollectionConfig,
        cache: Optional[ScanCache] = None,
        scan_id: str = "",
    ):
        self.graph = graph
        self.config = config
        self.cache = cache
        self.scan_id = scan_id

    async def execute(self) -> CollectorResult:
        """
        Execute the collector with timing, caching, and error handling.
        """
        result = CollectorResult(self.name)
        result.metadata["started_at"] = time.time()
        logger.info(f"[{self.name}] Starting collection...")

        try:
            # Check cache first
            if self.cache:
                cached = self.cache.get(f"collector:{self.name}")
                if cached:
                    logger.info(f"[{self.name}] Using cached data.")
                    result.data = cached
                    result.metadata["from_cache"] = True
                    result.metadata["completed_at"] = time.time()
                    return result

            # Run the actual collection
            await self.collect(result)

            # Cache the results
            if self.cache and result.data:
                self.cache.put(f"collector:{self.name}", result.data, self.scan_id)

        except Exception as e:
            result.add_error(f"Collection failed: {type(e).__name__}: {e}")
            logger.exception(f"[{self.name}] Collection failed")

        result.metadata["completed_at"] = time.time()
        result.metadata["duration_seconds"] = round(
            result.metadata["completed_at"] - result.metadata["started_at"], 2
        )
        logger.info(
            f"[{self.name}] Completed in {result.metadata['duration_seconds']}s — "
            f"{result.metadata['items_collected']} items"
        )
        return result

    @abstractmethod
    async def collect(self, result: CollectorResult):
        """
        Implement data collection logic.
        Add data to result via result.add_data(key, value).
        """
        raise NotImplementedError

    async def safe_get(self, endpoint: str, result: CollectorResult, **kwargs) -> dict:
        """Safely execute a GET and record errors without crashing."""
        try:
            data = await self.graph.get(endpoint, **kwargs)
            result.metadata["endpoints_queried"] += 1
            if data.get("_forbidden"):
                msg = data.get("_error_message", "Forbidden")
                result.add_warning(f"Permission denied: {endpoint} — {msg}")
                result.metadata.setdefault("permission_gaps", []).append(endpoint)
            return data
        except Exception as e:
            result.add_error(f"Failed to query {endpoint}: {e}")
            return {"value": []}

    async def safe_get_all(self, endpoint: str, result: CollectorResult, **kwargs) -> list:
        """Safely get all pages and record errors."""
        try:
            data = await self.graph.get_all_pages(endpoint, **kwargs)
            result.metadata["endpoints_queried"] += 1
            return data
        except GraphAPIError as e:
            if e.status_code == 403:
                result.add_warning(f"Permission denied: {endpoint} — {e}")
                result.metadata.setdefault("permission_gaps", []).append(endpoint)
            else:
                result.add_error(f"Failed to paginate {endpoint}: {e}")
            return []
        except Exception as e:
            result.add_error(f"Failed to paginate {endpoint}: {e}")
            return []

    async def safe_get_all_stream(self, endpoint: str, result: CollectorResult, **kwargs):
        """Safely stream all pages as a generator."""
        try:
            result.metadata["endpoints_queried"] += 1
            async for item in self.graph.get_all_pages_stream(endpoint, **kwargs):
                yield item
        except Exception as e:
            result.add_error(f"Failed to stream {endpoint}: {e}")
