from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlencode
import json
import urllib.request


@dataclass(frozen=True)
class StreamFlowClient:
    base_url: str
    api_password: str = ""
    proxy_auth: str = ""

    def health(self) -> dict:
        return self._json("/health")

    def metrics(self, password: str = "") -> str:
        headers = {"X-Metrics-Password": password} if password else {}
        return self._request("/metrics", headers=headers).decode("utf-8")

    def proxify(self, urls: str | Iterable[str], token: str | None = None) -> dict:
        values: list[tuple[str, str]] = []
        for url in [urls] if isinstance(urls, str) else urls:
            values.append(("url", url))
        if token:
            values.append(("token", token))
        body = urlencode(values).encode("utf-8")
        data = self._request(
            "/v0/proxy",
            method="POST",
            body=body,
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        return json.loads(data.decode("utf-8"))

    def store_addon_manifest(self, store: str = "rd") -> str:
        return f"{self._base()}/stremio/store/{store}/manifest.json"

    def wrap_addon_manifest(self) -> str:
        return f"{self._base()}/stremio/wrap/manifest.json"

    def _json(self, path: str) -> dict:
        return json.loads(self._request(path).decode("utf-8"))

    def _request(
        self,
        path: str,
        method: str = "GET",
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        merged = dict(headers or {})
        if self.api_password:
            merged["X-API-Password"] = self.api_password
        if self.proxy_auth:
            merged["X-StremThru-Authorization"] = self.proxy_auth
        request = urllib.request.Request(
            f"{self._base()}{path}",
            data=body,
            headers=merged,
            method=method,
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()

    def _base(self) -> str:
        return self.base_url.rstrip("/")
