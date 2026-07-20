"""
Layer 3: Edge case & adversarial robustness tests.

These run the full pipeline end-to-end (whitelist -> features ->
scaler -> model -> explain), the same path a real user hits through
main.py or the FastAPI service. The goal isn't "is the model right"
(that's test_model_evaluation.py) — it's "does the pipeline survive
weird, malformed, or adversarial input without crashing or returning
garbage." This is exactly the layer that would have caught the
torob.com query-string crash if it had existed before that bug shipped.
"""

import pytest
from predict import classify_url

REQUIRED_KEYS = {"url", "verdict", "confidence", "reasons"}


def assert_well_formed(result: dict):
    assert REQUIRED_KEYS.issubset(result.keys())
    assert result["verdict"] in ("phishing", "legitimate")
    assert 0.0 <= result["confidence"] <= 1.0
    assert isinstance(result["reasons"], list)


# ── things that should never crash the pipeline ──────────────────────

@pytest.mark.parametrize("url", [
    "https://example.com",
    "https://example.com/pages/support/?mode=chat&ticket_id=3347004",   # the torob.com crash
    "http://192.168.1.1/login",
    "http://user@evil.com",
    "https://" + "a" * 2000 + ".com",                                    # very long hostname
    "https://example.com/" + "x" * 2000,                                 # very long path
    "https://example.com:8443/secure",
    "https://xn--pple-43d.com",                                          # punycode (IDN homograph attempt)
    "http://example.com/?%00%01%02",                                     # control-char-ish query
    "https://example.com/path with spaces",
    "https://",
    "http://[::1]/login",                                                # IPv6 literal
])
def test_classify_url_never_crashes(url, model_and_scaler):
    model, scaler = model_and_scaler
    result = classify_url(url, model, scaler)
    assert_well_formed(result)


def test_empty_string_does_not_crash(model_and_scaler):
    model, scaler = model_and_scaler
    result = classify_url("", model, scaler)
    assert_well_formed(result)


# ── whitelist behavior ────────────────────────────────────────────────

def test_whitelisted_domain_bypasses_model(model_and_scaler):
    model, scaler = model_and_scaler
    result = classify_url("https://www.google.com/search?q=test", model, scaler)
    assert result["verdict"] == "legitimate"
    assert result["confidence"] == 1.0
    assert "whitelist" in result["reasons"][0].lower()


def test_lookalike_of_whitelisted_domain_is_not_bypassed(model_and_scaler):
    """
    google-secure-login.com is NOT google.com — tldextract must not
    treat it as trusted just because 'google' appears in the string.
    """
    model, scaler = model_and_scaler
    result = classify_url("http://google-secure-login.com/verify", model, scaler)
    # not asserting the verdict itself (that's the model's call) —
    # asserting the whitelist bypass specifically did NOT fire
    assert result["reasons"] != ["trusted domain (whitelist)"] or result["confidence"] != 1.0


# ── known adversarial patterns should surface in `reasons` when flagged ─

def test_ip_address_url_flagged_if_predicted_phishing(model_and_scaler):
    model, scaler = model_and_scaler
    result = classify_url("http://45.33.32.156/wp-login.php", model, scaler)
    assert_well_formed(result)
    if result["verdict"] == "phishing":
        assert any("ip address" in r.lower() for r in result["reasons"])


def test_at_symbol_url_flagged_if_predicted_phishing(model_and_scaler):
    model, scaler = model_and_scaler
    result = classify_url("http://www.paypal.com@malicious-site.tk/update", model, scaler)
    assert_well_formed(result)
    if result["verdict"] == "phishing":
        assert any("@" in r for r in result["reasons"])


# ── the specific www. regression, end-to-end this time ──────────────

def test_www_and_bare_domain_get_same_verdict(model_and_scaler):
    """
    End-to-end version of the features.py unit test: a www. prefix
    alone must not flip the verdict on an otherwise identical URL,
    since num_dots/num_subdomains now treat it as an alias everywhere.
    """
    model, scaler = model_and_scaler
    bare = classify_url("https://example-test-site.com/products", model, scaler)
    www = classify_url("https://www.example-test-site.com/products", model, scaler)
    assert bare["verdict"] == www["verdict"]
    
