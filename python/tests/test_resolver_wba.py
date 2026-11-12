"""Web Bot Auth directory fetching: SSRF limits, caching, proofs."""

import socket
import threading
import time

import pytest

from agentpin import httpsig, net, wba
from agentpin.httpsig import HttpRequest
from agentpin.net import FetchedResponse, fetch_bounded, is_non_public
from agentpin.resolver_wba import CachingDirectoryResolver, DirectoryFetchOptions, _max_age, fetch_directory
from agentpin.types import AgentPinError
from agentpin.wba import DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, Directory, SignOptions, VerifyOptions


class Server:
    """HTTP/1.1 server that answers every connection with ``respond(url)``; counts connections."""

    def __init__(self, respond):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        host, port = self.sock.getsockname()
        self.url = f"http://{host}:{port}{DIRECTORY_PATH}"
        self.response = respond(self.url)
        self.hits = 0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.recv(4096)
                self.hits += 1
                conn.sendall(self.response)


def http(status, headers, body):
    out = f"HTTP/1.1 {status}\r\n".encode()
    for k, v in headers:
        out += f"{k}: {v}\r\n".encode()
    return out + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body


def serve(response):
    return Server(lambda _url: response)


def local_opts(**kw):
    return DirectoryFetchOptions(public_only=False, require_https=False, **kw)


def test_fetches_signed_directory_and_caches_it():
    key = wba.generate_signing_key()
    body = Directory.from_keys([key.public_key()]).to_json()

    def respond(url):
        authority = httpsig.parse_url(url).authority
        headers = wba.sign_directory_response(body, authority, [key], int(time.time()), 3600)
        headers += [("Content-Type", DIRECTORY_MEDIA_TYPE), ("Cache-Control", "max-age=600")]
        return http("200 OK", headers, body)

    srv = Server(respond)
    directory, ttl = fetch_directory(srv.url, local_opts(require_proof=True))
    assert len(directory.keys) == 1 and ttl == 600

    resolver = CachingDirectoryResolver(local_opts())
    tp = wba.thumbprint(key.public_key())
    srv.hits = 0
    assert resolver.lookup(srv.url, tp) == key.public_key()
    assert resolver.lookup(srv.url, tp) == key.public_key()
    assert srv.hits == 1, "second lookup is cached"
    # A key the directory does not publish: resolved, not found.
    assert resolver.lookup(srv.url, wba.thumbprint(wba.generate_signing_key().public_key())) is None


def test_failed_fetch_keeps_cached_directory():
    key = wba.generate_signing_key()
    tp = wba.thumbprint(key.public_key())
    url = f"http://127.0.0.1:9{DIRECTORY_PATH}"
    resolver = CachingDirectoryResolver(local_opts(timeout=2))
    resolver.insert(url, Directory.from_keys([key.public_key()]))  # stale copy
    assert resolver.lookup(url, tp) == key.public_key()
    with pytest.raises(AgentPinError):
        CachingDirectoryResolver(local_opts(timeout=2)).lookup(url, tp)


def test_refuses_unsafe_directories():
    body = b'{"keys":[]}'
    srv = serve(http("302 Found", [("Location", "http://127.0.0.1:9/")], body))
    with pytest.raises(AgentPinError, match="Redirect"):
        fetch_directory(srv.url, local_opts())

    srv = serve(http("404 Not Found", [], body))
    with pytest.raises(AgentPinError, match="HTTP 404"):
        fetch_directory(srv.url, local_opts())

    # Default options: http and loopback are refused before connecting.
    srv = serve(http("200 OK", [], body))
    with pytest.raises(AgentPinError):
        fetch_directory(srv.url)
    with pytest.raises(AgentPinError):
        fetch_directory(srv.url, DirectoryFetchOptions(require_https=False))
    with pytest.raises(AgentPinError):
        fetch_directory(srv.url.replace("127.0.0.1", "localhost"), DirectoryFetchOptions(require_https=False))
    assert srv.hits == 0

    # Size cap: by Content-Length and while streaming.
    big = b'{"keys":[' + b" " * (70 * 1024) + b"]}"
    srv = serve(http("200 OK", [], big))
    with pytest.raises(AgentPinError, match="exceeds"):
        fetch_directory(srv.url, local_opts())
    srv = serve(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + big)
    with pytest.raises(AgentPinError, match="exceeds"):
        fetch_directory(srv.url, local_opts())

    # Too many keys.
    many = ('{"keys":[' + ",".join(["{}"] * 65) + "]}").encode()
    srv = serve(http("200 OK", [], many))
    with pytest.raises(AgentPinError, match="too many keys"):
        fetch_directory(srv.url, local_opts())

    # require_proof drops unsigned keys.
    key = wba.generate_signing_key()
    body = Directory.from_keys([key.public_key()]).to_json()
    srv = serve(http("200 OK", [("Content-Digest", httpsig.content_digest(body))], body))
    assert fetch_directory(srv.url, local_opts(require_proof=True))[0].keys == []
    assert len(fetch_directory(srv.url, local_opts())[0].keys) == 1


def test_connection_goes_to_the_vetted_address(monkeypatch):
    """The host is resolved once and the connection is made to that address:
    a resolver answering differently on a second query cannot redirect it."""
    srv = serve(http("200 OK", [], b'{"keys":[]}'))
    port = int(srv.url.split(":")[2].split("/")[0])
    calls = []
    real = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        calls.append(host)
        if host == "rebind.test":
            # First answer is the (allowed, in this test) local server; any
            # later answer would point elsewhere.
            ip = "127.0.0.1" if len(calls) == 1 else "10.9.9.9"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    resp = fetch_bounded(f"http://rebind.test:{port}/x", "application/json", public_only=False, timeout=3)
    assert resp.status == 200 and calls.count("rebind.test") == 1

    # With public_only, a name resolving only to non-public addresses is refused.
    calls.clear()
    with pytest.raises(AgentPinError, match="non-public"):
        fetch_bounded(f"http://rebind.test:{port}/x", "application/json", timeout=3)
    assert srv.hits == 1


def test_mixed_answers_use_only_public_addresses(monkeypatch):
    connected = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
        ]

    def fake_connect(address, timeout=None, *args, **kwargs):
        connected.append(address[0])
        raise OSError("no network in tests")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", fake_connect)
    with pytest.raises(AgentPinError, match="Failed to fetch"):
        fetch_bounded("https://mixed.test/", "application/json", timeout=3)
    assert connected == ["93.184.216.34"]


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
        "0.1.2.3", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
        "240.0.0.1", "255.255.255.255", "::1", "::", "fc00::1", "fd12::1", "fe80::1", "ff02::1",
        "2001:db8::1", "64:ff9b::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    ],
)
def test_non_public_addresses(ip):
    assert is_non_public(ip)


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_addresses(ip):
    assert not is_non_public(ip)


def test_literal_non_public_hosts_refused_without_connecting(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not resolve")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for url in ["https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest", "https://0x7f.1/"]:
        with pytest.raises(AgentPinError, match="non-public"):
            fetch_bounded(url, "application/json")


def test_injected_fetcher_and_status():
    def fetch(url, accept, **kw):
        assert DIRECTORY_MEDIA_TYPE in accept and kw["max_bytes"] == 64 * 1024 and kw["public_only"]
        return FetchedResponse(500, [], b"")

    with pytest.raises(AgentPinError, match="HTTP 500"):
        fetch_directory("https://agent.example/d", fetch=fetch)


def test_ttl_clamped():
    def fetch_with(cc):
        def fetch(url, accept, **kw):
            return FetchedResponse(200, [("cache-control", cc)], b'{"keys":[]}')

        return fetch

    assert fetch_directory("https://a.example/d", fetch=fetch_with("max-age=5"))[1] == 60
    assert fetch_directory("https://a.example/d", fetch=fetch_with("max-age=999999"))[1] == 86400
    assert fetch_directory("https://a.example/d", fetch=fetch_with("no-cache"))[1] == 3600


def test_parses_max_age():
    assert _max_age([("Cache-Control", "public, max-age=120")]) == 120
    assert _max_age([]) is None
    assert _max_age([("Cache-Control", "max-age=abc")]) is None


def test_caching_resolver_verifies_requests():
    key = wba.generate_signing_key()
    agent = "https://agent.example/.well-known/http-message-signatures-directory"
    body = Directory.from_keys([key.public_key()]).to_json()
    fetched = []

    def fetch(url, accept, **kw):
        fetched.append(url)
        return FetchedResponse(200, [], body)

    resolver = CachingDirectoryResolver(fetch=fetch)
    req = HttpRequest("GET", "https://origin.example/")
    wba.sign_request(req, key, agent, SignOptions()).apply(req)
    assert wba.verify_request(req, resolver, VerifyOptions()).verified
    assert fetched == [agent]
    other = wba.generate_signing_key()
    assert wba.verify_request(req, CachingDirectoryResolver(fetch=lambda *a, **k: FetchedResponse(
        200, [], Directory.from_keys([other.public_key()]).to_json())), VerifyOptions()).unverified

    def failing(url, accept, **kw):
        raise AgentPinError(net._fail("down").code, "down")

    assert wba.verify_request(req, CachingDirectoryResolver(fetch=failing), VerifyOptions()).unverified
