"""Tests for the hardened fetch layer (AP-7, AP-12, AP-13)."""

import http.server
import threading
import time

import pytest

from agentpin.net import fetch_json_bounded
from agentpin.types import AgentPinError


class _Resp:
    def __init__(self, status, headers=None, body=b"", chunks=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self._chunks = chunks

    def iter_content(self, chunk_size=8192):
        if self._chunks is not None:
            yield from self._chunks
            return
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        pass


def _get(resp):
    def get(url, **kwargs):
        assert kwargs.get("allow_redirects") is False
        assert kwargs.get("stream") is True
        assert kwargs.get("timeout")
        return resp

    return get


def test_fetches_small_json():
    doc = fetch_json_bounded(
        "https://example.com/x",
        http_get_impl=_get(_Resp(200, {"Content-Type": "application/json; charset=utf-8"}, b'{"a":1}')),
    )
    assert doc == {"a": 1}


def test_rejects_redirect():
    with pytest.raises(AgentPinError, match="Redirect rejected"):
        fetch_json_bounded(
            "https://example.com/x",
            http_get_impl=_get(_Resp(302, {"Location": "https://evil.example/", "Content-Type": "application/json"})),
        )


def test_rejects_oversized_by_content_length_and_streaming():
    with pytest.raises(AgentPinError, match="exceeds"):
        fetch_json_bounded(
            "https://example.com/x",
            max_bytes=1024,
            http_get_impl=_get(_Resp(200, {"Content-Type": "application/json", "Content-Length": "2048"}, b" " * 2048)),
        )
    with pytest.raises(AgentPinError, match="exceeds"):
        fetch_json_bounded(
            "https://example.com/x",
            max_bytes=1024,
            http_get_impl=_get(_Resp(200, {"Content-Type": "application/json"}, chunks=[b"x" * 1024] * 4)),
        )


def test_rejects_non_json_content_type():
    with pytest.raises(AgentPinError, match="not application/json"):
        fetch_json_bounded("https://example.com/x", http_get_impl=_get(_Resp(200, {"Content-Type": "text/html"}, b"{}")))


def test_not_found_is_none():
    assert fetch_json_bounded("https://example.com/x", http_get_impl=_get(_Resp(404))) is None


def test_times_out_on_stalled_server_with_generic_error():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            time.sleep(2)

        def log_message(self, *args):  # noqa: D401
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/doc.json"
    try:
        start = time.monotonic()
        with pytest.raises(AgentPinError) as exc:
            fetch_json_bounded(url, timeout=0.3)
        assert str(exc.value) == f"Failed to fetch {url}"
        assert time.monotonic() - start < 2
    finally:
        server.shutdown()


def test_real_redirect_is_rejected_by_default_http_get():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/evil")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/doc.json"
    try:
        with pytest.raises(AgentPinError, match="Redirect rejected"):
            fetch_json_bounded(url)
    finally:
        server.shutdown()
