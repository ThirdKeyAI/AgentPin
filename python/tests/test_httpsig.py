"""RFC 9421 HTTP message signatures and the Structured Field codec."""

from decimal import Decimal

import pytest

from agentpin import httpsig
from agentpin.httpsig import (
    ALG_RSA_PSS_SHA512,
    Component,
    Date,
    DisplayString,
    HttpRequest,
    HttpResponse,
    InnerList,
    Item,
    PrivateKey,
    PublicKey,
    StructuredFieldError,
    Token,
    component_value,
    content_digest,
    content_digest_matches,
    parse_sf_dictionary,
    parse_sf_item,
    parse_signatures,
    parse_url,
    serialize_sf_dictionary,
    serialize_sf_item,
    sign,
    verify,
)
from agentpin.types import AgentPinError, ErrorCode

RFC_ED25519_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n"
    "-----END PRIVATE KEY-----\n"
)


def rfc_key():
    return PrivateKey.from_pem(RFC_ED25519_PEM)


def signed(req, fields):
    return req.header("Signature-Input", fields.signature_input).header("Signature", fields.signature)


# --- Structured fields -------------------------------------------------------


def test_sf_dictionary_roundtrip_all_types():
    text = 'a=1, b=-2.5, c="x\\"y\\\\", d=tok/en:1, e=:AQID:, f=?0, g, h=@1659578233, i=%"f%c3%bc", j=(1 "two");p'
    d = parse_sf_dictionary(text)
    assert d["a"] == Item(1)
    assert d["b"] == Item(Decimal("-2.5"))
    assert d["c"] == Item('x"y\\')
    assert d["d"] == Item(Token("tok/en:1"))
    assert d["e"] == Item(b"\x01\x02\x03")
    assert d["f"] == Item(False)
    assert d["g"] == Item(True)
    assert d["h"] == Item(Date(1659578233))
    assert d["i"] == Item(DisplayString("fü"))
    assert d["j"] == InnerList([Item(1), Item("two")], {"p": True})
    assert serialize_sf_dictionary(d) == text


def test_sf_parsing_is_strict():
    for bad in [
        "A=1",  # uppercase key
        "a=1,",  # trailing comma
        "a=1 b=2",  # missing comma
        'a="unterminated',
        'a="bad\\x"',
        "a=1234567890123456",  # 16 digits
        "a=1234567890123.1",  # 13 integer digits
        "a=1.1234",  # 4 fraction digits
        "a=1.",
        "a=?2",
        "a=(1 2",
        "a=(1,2)",
        "a=:@@@@:",
        "a=@1.5",
        'a=%"%C3"',  # uppercase hex
        'a=%"%ff"',  # invalid UTF-8
        "a=é",
    ]:
        with pytest.raises(StructuredFieldError):
            parse_sf_dictionary(bad)
    assert parse_sf_dictionary("") == {}
    with pytest.raises(StructuredFieldError):
        parse_sf_item("")
    with pytest.raises(StructuredFieldError):
        parse_sf_item('"a" x')


def test_sf_byte_sequence_padding_is_lenient_like_sfv():
    assert parse_sf_item(":AQI:").value == b"\x01\x02"
    assert parse_sf_item(":AQI=:").value == b"\x01\x02"
    with pytest.raises(StructuredFieldError):
        parse_sf_item(":AQI==:")
    with pytest.raises(StructuredFieldError):
        parse_sf_item(":A:")


def test_sf_duplicate_keys_overwrite_in_place():
    d = parse_sf_dictionary("a=1, b=2, a=3")
    assert list(d) == ["a", "b"] and d["a"] == Item(3)


def test_sf_serialization_rules():
    assert serialize_sf_item(Item(Decimal("1.0005"))) == "1.0"
    assert serialize_sf_item(Item(Decimal("-0.25"))) == "-0.25"
    assert serialize_sf_item(Item(True, {"a": True, "b": False})) == "?1;a;b=?0"
    with pytest.raises(StructuredFieldError):
        serialize_sf_item(Item(10**15))
    with pytest.raises(StructuredFieldError):
        serialize_sf_item(Item("tab\there"))
    with pytest.raises(StructuredFieldError):
        serialize_sf_dictionary({"Bad": Item(1)})


# --- URLs ---------------------------------------------------------------------


def test_url_normalization():
    assert str(parse_url("HTTPS://Example.COM:443")) == "https://example.com/"
    assert str(parse_url("https://a.test/x/../y/./z?q=1 2#f")) == "https://a.test/y/z?q=1%202#f"
    assert str(parse_url("http://0x7f.1/")) == "http://127.0.0.1/"
    assert str(parse_url("https://[::FFFF:1.2.3.4]:8443/")) == "https://[::ffff:102:304]:8443/"
    assert parse_url("https://example.com?").query == ""
    for bad in ["/relative", "https://", "https://a.test:99999/", "mailto:x@y", "https://[::1/"]:
        with pytest.raises(ValueError):
            parse_url(bad)


# --- RFC 9421 -----------------------------------------------------------------


def test_rfc9421_b26_ed25519_vector():
    req = HttpRequest(
        "POST",
        "https://example.com/foo?param=Value&Pet=dog",
        [
            ("Host", "example.com"),
            ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("Content-Type", "application/json"),
            ("Content-Length", "18"),
        ],
    )
    components = [Component(n) for n in ("date", "@method", "@path", "@authority", "content-type", "content-length")]
    params = [("created", 1618884473), ("keyid", "test-key-ed25519")]
    f = sign(req, "sig-b26", components, params, rfc_key())
    assert f.signature == (
        "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
    )
    assert f.signature_input == (
        'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")'
        ';created=1618884473;keyid="test-key-ed25519"'
    )
    s = signed(req, f)
    parsed = parse_signatures(s.headers)
    assert len(parsed) == 1
    verify(s, parsed[0], rfc_key().public_key())


def test_tampered_component_fails():
    req = HttpRequest("GET", "https://example.com/a")
    f = sign(req, "s", [Component("@authority"), Component("@path")], [("created", 1)], rfc_key())
    moved = HttpRequest("GET", "https://example.com/b", [("Signature-Input", f.signature_input)])
    moved.headers.append(("Signature", f.signature))
    parsed = parse_signatures(moved.headers)
    with pytest.raises(AgentPinError) as e:
        verify(moved, parsed[0], rfc_key().public_key())
    assert e.value.code == ErrorCode.SIGNATURE_INVALID


def test_derived_components():
    req = HttpRequest("GET", "https://Example.COM:8443/p/q?x=1")

    def v(n):
        return component_value(req, Component(n))

    assert v("@authority") == "example.com:8443"
    assert v("@scheme") == "https"
    assert v("@path") == "/p/q"
    assert v("@query") == "?x=1"
    assert v("@request-target") == "/p/q?x=1"
    assert v("@target-uri") == "https://example.com:8443/p/q?x=1"
    plain = HttpRequest("GET", "https://example.com")
    assert component_value(plain, Component("@authority")) == "example.com"
    assert component_value(plain, Component("@path")) == "/"
    assert component_value(plain, Component("@query")) == "?"
    with pytest.raises(AgentPinError):
        component_value(plain, Component("@status"))
    resp = HttpResponse(200, [], plain)
    assert component_value(resp, Component("@status")) == "200"
    assert component_value(resp, Component.of_request("@authority")) == "example.com"
    with pytest.raises(AgentPinError):
        component_value(HttpResponse(200), Component.of_request("@authority"))


def test_combined_fields_and_dictionary_members():
    req = HttpRequest(
        "GET",
        "https://example.com",
        [("X-A", " one "), ("x-a", "two"), ("Sig-Agent", 'a="https://a.test", b="https://b.test"')],
    )
    assert component_value(req, Component("x-a")) == "one, two"
    assert component_value(req, Component.keyed("sig-agent", "b")) == '"https://b.test"'
    with pytest.raises(AgentPinError):
        component_value(req, Component.keyed("sig-agent", "c"))
    with pytest.raises(AgentPinError):
        component_value(req, Component("missing"))


@pytest.mark.parametrize(
    "value",
    [
        's=("Date");created=1',
        's=("date";sf);created=1',
        's=("date";bs);created=1',
        's=("date";tr);created=1',
        's=("@signature-params");created=1',
        's=("date" "date");created=1',
        's=("@method";key="x");created=1',
        's=("@query-param");created=1',
        's=("@method";name="x");created=1',
        's=("@query-param";name="a";name="b";key="k");created=1',
        's=("date";req=?0);created=1',
        's=(date);created=1',
        's="date"',
        's=("date");created="1"',
        's=("date");keyid=tok',
    ],
)
def test_rejects_bad_identifiers(value):
    with pytest.raises(AgentPinError):
        parse_signatures([("Signature-Input", value), ("Signature", "s=:AAAA:")])


def test_rejects_missing_or_wrong_signature_member():
    with pytest.raises(AgentPinError):
        parse_signatures([("Signature-Input", 's=("date");created=1')])
    with pytest.raises(AgentPinError):
        parse_signatures([("Signature-Input", 's=("date");created=1'), ("Signature", 's="AAAA"')])


def test_unknown_params_are_ignored_but_covered():
    req = HttpRequest("GET", "https://example.com/", [("Signature-Input", 's=("@authority");created=1;extra=5')])
    parsed = parse_signatures([*req.headers, ("Signature", "s=:AAAA:")])
    assert parsed[0].params.created == 1
    assert parsed[0].signature_base(req).endswith('("@authority");created=1;extra=5')


def test_sign_rejects_duplicates_and_bad_params():
    req = HttpRequest("GET", "https://example.com/")
    with pytest.raises(AgentPinError):
        sign(req, "s", [Component("@authority"), Component("@authority")], [], rfc_key())
    with pytest.raises(AgentPinError):
        sign(req, "s", [Component("@authority")], [("created", 1), ("created", 2)], rfc_key())
    with pytest.raises(AgentPinError):
        sign(req, "s", [Component("@authority")], [("keyid", "ü")], rfc_key())
    with pytest.raises(AgentPinError):
        sign(req, "Bad", [Component("@authority")], [], rfc_key())
    with pytest.raises(AgentPinError):
        sign(req.header("X", "a\nb"), "s", [Component("x")], [], rfc_key())


def test_content_digest_roundtrip():
    body = b'{"hello": "world"}\n'
    assert content_digest(body) == "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:"
    h = [("Content-Digest", content_digest(body))]
    assert content_digest_matches(h, body)
    assert not content_digest_matches(h, b"other")
    assert not content_digest_matches([], body)
    assert not content_digest_matches([("Content-Digest", "not a dict(")], body)


def test_query_param_values():
    req = HttpRequest(
        "GET",
        "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value"
        "&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&dup=1&dup=2&qux=",
    )

    def v(n):
        return component_value(req, Component.query_param(n))

    assert v("var") == "this%20is%20a%20big%0Amultiline%20value"
    assert v("bar") == "with%20plus%20whitespace"
    assert v('façade": ') == "something"
    assert v("qux") == ""
    with pytest.raises(AgentPinError):
        v("dup")
    with pytest.raises(AgentPinError):
        v("missing")
    assert Component.query_param('façade": ').identifier() == '"@query-param";name="fa%C3%A7ade%22%3A%20"'

    f = sign(req, "s", [Component.query_param("var"), Component("@authority")], [("created", 1)], rfc_key())
    s = signed(req, f)
    parsed = parse_signatures(s.headers)
    assert parsed[0].covers(Component.query_param("var"))
    verify(s, parsed[0], rfc_key().public_key())


def test_alg_parameter_must_match_key():
    req = HttpRequest("GET", "https://example.com/")
    f = sign(req, "s", [Component("@authority")], [("alg", ALG_RSA_PSS_SHA512)], rfc_key())
    s = signed(req, f)
    with pytest.raises(AgentPinError):
        verify(s, parse_signatures(s.headers)[0], rfc_key().public_key())


def test_ed25519_strict_verification_rejects_small_order_keys():
    identity = bytes([1]) + bytes(31)
    weak = PublicKey.ed25519(identity)
    with pytest.raises(AgentPinError):
        weak.verify(b"msg", identity + bytes(32))
    with pytest.raises(AgentPinError):
        PublicKey.ed25519(bytes([2]) + bytes(31))  # not a curve point


def test_key_loading():
    assert rfc_key().public_key() == rfc_key().public_key()
    for bad in ["not a key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"]:
        with pytest.raises(AgentPinError) as e:
            PrivateKey.from_pem(bad)
        assert e.value.code == ErrorCode.INVALID_KEY_FORMAT
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    ec_pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode()
    )
    with pytest.raises(AgentPinError):
        PrivateKey.from_pem(ec_pem)
    short = (
        rsa.generate_private_key(65537, 1024)
        .private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
        .decode()
    )
    with pytest.raises(AgentPinError):
        PrivateKey.from_pem(short)
    assert httpsig.PrivateKey.generate().alg == "ed25519"
