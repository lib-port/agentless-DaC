"""Bounded HTTPS transfer, isolated from evidence, credentials and pack parsing."""

from __future__ import annotations

import os
import ssl
import time
import urllib.request
from typing import Any
from urllib.parse import urlparse

from detection_goggles.errors import DacError


def _url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DacError("Downloads require credential-free HTTPS")
    return value


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        return super().redirect_request(req, fp, code, msg, headers, _url(newurl))


def handle(request: dict[str, Any]) -> dict[str, Any]:
    from detection_goggles.runtime_guard import require_container

    require_container("download")
    limit = request.get("limit")
    if limit not in {1024**2, 64 * 1024**2}:
        raise DacError("Unsupported download limit")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _Redirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    started = time.monotonic()
    query = urllib.request.Request(
        _url(request["url"]), headers={"User-Agent": "detection-goggles"}
    )
    with opener.open(query, timeout=15) as response:
        announced = response.headers.get("Content-Length")
        if announced is not None and not 0 <= int(announced) <= limit:
            raise DacError("Download exceeds the size limit")
        descriptor = os.open("/output/download", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            size = 0
            while True:
                if time.monotonic() - started > 120:
                    raise DacError("Download exceeded its time limit")
                chunk = response.read(min(1024**2, limit - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise DacError("Download exceeds the size limit")
                handle.write(chunk)
    return {"exit_code": 0, "size": size}
