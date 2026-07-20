"""
Layer 1: Feature extraction unit tests.

These test features.py in isolation — no model, no dataset needed.
This is the layer that would have caught the v1.1.1 www-stripping
drift bug immediately: if predict.py and feature_extractor.py ever
diverge again (e.g. someone adds a feature to one and forgets the
other), test_all_feature_funcs_present will fail loudly instead of
silently producing wrong predictions in production.
"""

import pytest
from features import (
    FEATURE_FUNCS,
    extract_features,
    get_num_dots,
    get_num_subdomains,
    get_has_ip_address,
    get_has_at_symbol,
    get_uses_https,
    get_has_port,
    get_has_login_keywords,
    get_has_login_path,
)


# ── www.-stripping regression tests (the exact v1.1.1 bug) ──────────

@pytest.mark.parametrize("bare,with_www", [
    ("https://example.com/path", "https://www.example.com/path"),
    ("https://sub.example.com", "https://www.sub.example.com"),
    ("http://a.b.c.example.com", "http://www.a.b.c.example.com"),
])
def test_www_prefix_does_not_change_num_dots(bare, with_www):
    """www. is an alias, not a real subdomain — must not inflate num_dots."""
    assert get_num_dots(bare) == get_num_dots(with_www)


@pytest.mark.parametrize("bare,with_www", [
    ("https://example.com", "https://www.example.com"),
    ("https://sub.example.com", "https://www.sub.example.com"),
])
def test_www_prefix_does_not_change_num_subdomains(bare, with_www):
    assert get_num_subdomains(bare) == get_num_subdomains(with_www)


def test_www_itself_is_not_counted_as_a_subdomain():
    assert get_num_subdomains("https://www.example.com") == 0


def test_real_subdomain_is_still_counted():
    assert get_num_subdomains("https://mail.example.com") == 1
    assert get_num_subdomains("https://a.b.example.com") == 2


# ── individual feature correctness ───────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("http://192.168.1.1/login", 1),
    ("http://8.8.8.8", 1),
    ("https://example.com", 0),
    ("https://192.168.1.1.example.com", 0),  # IP-looking substring, not the host
])
def test_has_ip_address(url, expected):
    assert get_has_ip_address(url) == expected


@pytest.mark.parametrize("url,expected", [
    ("http://user@evil.com", 1),
    ("http://www.amazon.com@malicious-site.com/update", 1),
    ("https://example.com", 0),
])
def test_has_at_symbol(url, expected):
    assert get_has_at_symbol(url) == expected


@pytest.mark.parametrize("url,expected", [
    ("https://example.com", 1),
    ("http://example.com", 0),
])
def test_uses_https(url, expected):
    assert get_uses_https(url) == expected


@pytest.mark.parametrize("url,expected", [
    ("http://example.com:8080/login", 1),
    ("https://example.com:443/login", 0),
    ("http://example.com:80", 0),
    ("https://example.com", 0),
])
def test_has_port(url, expected):
    assert get_has_port(url) == expected


def test_login_in_hostname_vs_path_are_distinguished():
    """login.ru is spoofing; /auth/login is a normal endpoint — must not conflate."""
    assert get_has_login_keywords("http://login.ru/secure") == 1
    assert get_has_login_keywords("https://example.com/auth/login") == 0
    assert get_has_login_path("https://example.com/auth/login") == 1
    assert get_has_login_path("http://login.ru/secure") == 0


# ── structural consistency ───────────────────────────────────────────

def test_extract_features_returns_all_expected_keys():
    features = extract_features("https://example.com/path?x=1")
    assert set(features.keys()) == set(FEATURE_FUNCS.keys())


def test_extract_features_matches_individual_functions():
    """
    This is the drift-detector: extract_features() must produce exactly
    what you'd get calling each FEATURE_FUNCS entry directly. If someone
    reintroduces a local override anywhere, this catches it.
    """
    url = "http://www.paypal-verify.login.ru/secure/account/confirm"
    features = extract_features(url)
    for name, func in FEATURE_FUNCS.items():
        assert features[name] == func(url), f"mismatch on feature '{name}'"


def test_extract_features_handles_empty_string():
    features = extract_features("")
    assert features["url_length"] == 0


@pytest.mark.parametrize("url", [
    "not a url at all",
    "http://",
    "https://[invalid-ipv6",
    "http://256.256.256.256",
])
def test_extract_features_never_raises_on_malformed_input(url):
    """Malformed input should degrade to safe defaults, never crash."""
    extract_features(url)  # just must not raise
