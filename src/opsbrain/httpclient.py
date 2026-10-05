"""Tiny HTTP client for Prometheus, Loki and health checks. Only URLs from the config are ever requested."""

from __future__ import annotations

import time
from typing import Any

import httpx

from .util import OpsError


class HttpClient:
    def __init__(self, *, verify_tls: bool = True):
        self.verify_tls = verify_tls

    def get_json(self, url: str, params: dict[str, Any] | None = None, timeout: float = 20) -> Any:
        try:
            response = httpx.get(url, params=params, timeout=timeout, verify=self.verify_tls, follow_redirects=True)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OpsError(f"GET {url.split('?')[0]}: {type(exc).__name__}: {str(exc)[:200]}") from exc

    def check(self, url: str, timeout: float = 10) -> tuple[int, int]:
        """(status code or 0 on a transport error, milliseconds)."""
        started = time.monotonic()
        try:
            status = httpx.get(url, timeout=timeout, verify=self.verify_tls, follow_redirects=False).status_code
        except httpx.HTTPError:
            status = 0
        return status, int((time.monotonic() - started) * 1000)
