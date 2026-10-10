"""Hardened HTTP fetching shared by every network resolver.

Every outbound request made by this package goes through
:func:`fetch_json_bounded`, which enforces the network defaults the spec and
the security review require (AP-7, AP-12, AP-13): redirects are never
followed, a request timeout bounds stalls, the response body is capped both
by ``Content-Length`` and while streaming, the response must carry a JSON
``Content-Type``, and error strings are generic (URL and failure class, never
transport detail).
"""

import json
from typing import Any, Callable, Optional

from .types import AgentPinError, ErrorCode

DEFAULT_TIMEOUT_SECS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 1 << 20


def _default_http_get(url: str, **kwargs: Any) -> Any:
    import requests  # local import keeps `requests` an optional dependency

    return requests.get(url, **kwargs)


#: The GET implementation used by :func:`fetch_json_bounded`. Replaceable in
#: tests. It must accept ``url`` plus ``headers``, ``stream``,
#: ``allow_redirects`` and ``timeout`` keyword arguments and return an object
#: with ``status_code``, ``headers`` (mapping) and ``iter_content(chunk_size)``.
http_get: Callable[..., Any] = _default_http_get


def _is_json_content_type(value: Optional[str]) -> bool:
    if not isinstance(value, str):
        return False
    media = value.split(";")[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def _fail(message: str) -> AgentPinError:
    return AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, message)


def fetch_json_bounded(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECS,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    http_get_impl: Optional[Callable[..., Any]] = None,
) -> Optional[Any]:
    """GET ``url`` and return its parsed JSON body, or ``None`` on HTTP 404.

    Rejects redirects, non-success statuses, non-JSON content types and
    bodies larger than ``max_bytes``.
    """
    get = http_get_impl or http_get
    try:
        resp = get(
            url,
            headers={"Accept": "application/json"},
            stream=True,
            allow_redirects=False,
            timeout=timeout,
        )
    except Exception:
        raise _fail(f"Failed to fetch {url}") from None

    try:
        status = int(getattr(resp, "status_code", 0))
        if 300 <= status < 400:
            raise _fail(f"Redirect rejected fetching {url} (status {status})")
        if status == 404:
            return None
        if not 200 <= status < 300:
            raise _fail(f"HTTP {status} fetching {url}")
        headers = getattr(resp, "headers", {}) or {}
        if not _is_json_content_type(headers.get("Content-Type") or headers.get("content-type")):
            raise _fail(f"Response from {url} is not application/json")
        content_length = headers.get("Content-Length") or headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > max_bytes:
                    raise _fail(f"Response from {url} exceeds {max_bytes} bytes")
            except ValueError:
                raise _fail(f"Invalid Content-Length from {url}") from None
        chunks = []
        total = 0
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise _fail(f"Response from {url} exceeds {max_bytes} bytes")
                chunks.append(chunk)
        except AgentPinError:
            raise
        except Exception:
            raise _fail(f"Failed to read response from {url}") from None
        try:
            return json.loads(b"".join(chunks).decode("utf-8"))
        except Exception:
            raise _fail(f"Invalid JSON from {url}") from None
    finally:
        close = getattr(resp, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
