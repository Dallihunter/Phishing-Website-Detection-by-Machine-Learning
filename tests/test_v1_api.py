import pytest
from predict import classify_url_v1
from signals import compute_severity, is_short_bare_domain_edge_case


def test_whitelisted_domain_is_clean(model_and_scaler):
    model, scaler = model_and_scaler
    r = classify_url_v1("https://www.google.com", model, scaler)
    assert r["verdict"] == "clean"
    assert r["severity"] == "clean"
    assert r["signals"][0]["code"] == "WHITELISTED_DOMAIN"


def test_ip_address_url_has_signal_code(model_and_scaler):
    model, scaler = model_and_scaler
    r = classify_url_v1("http://45.33.32.156/wp-login.php", model, scaler)
    if r["verdict"] == "malicious":
        codes = [s["code"] for s in r["signals"]]
        assert "HAS_IP_ADDRESS" in codes


def test_include_whois_false_has_no_age_signal(model_and_scaler):
    model, scaler = model_and_scaler
    r = classify_url_v1("http://paypal-verify.login.ru/secure", model, scaler, include_whois=False)
    assert r["domain_age_days"] is None
    codes = [s["code"] for s in r["signals"]]
    assert "DOMAIN_AGE_UNKNOWN" not in codes
    assert "DOMAIN_RECENTLY_REGISTERED" not in codes


def test_failed_whois_lookup_gives_unknown_code_not_bare_negative_one(model_and_scaler):
    model, scaler = model_and_scaler
    r = classify_url_v1("http://paypal-verify.login.ru/secure", model, scaler, include_whois=True)
    if r["domain_age_days"] == -1:
        codes = [s["code"] for s in r["signals"]]
        assert "DOMAIN_AGE_UNKNOWN" in codes


def test_severity_valid_values(model_and_scaler):
    model, scaler = model_and_scaler
    for url in ["https://example.com", "http://192.168.1.1/login", "http://user@evil.com"]:
        r = classify_url_v1(url, model, scaler)
        assert r["severity"] in ("critical", "high", "medium", "low", "clean")


# ── compute_severity unit tests (no model needed) ────────────────────

def make_features(**overrides):
    base = {
        "has_ip_address": 0, "has_at_symbol": 0, "uses_https": 1,
        "has_suspicious_words": 0, "has_login_keywords": 0,
        "hostname_hyphens": 0, "hostname_length": 20, "path_length": 20,
    }
    base.update(overrides)
    return base


def test_legitimate_no_signals_is_clean():
    f = make_features()
    assert compute_severity("legitimate", 0.1, f) == "clean"


def test_legitimate_with_signal_is_low():
    f = make_features(uses_https=0)
    assert compute_severity("legitimate", 0.3, f) == "low"


def test_short_bare_domain_capped_at_medium():
    f = make_features(hostname_length=10, path_length=0, has_ip_address=1)
    assert is_short_bare_domain_edge_case(f) is True
    assert compute_severity("phishing", 0.99, f) == "medium"


def test_high_confidence_with_risk_signal_is_critical():
    f = make_features(has_ip_address=1, hostname_length=30, path_length=20)
    assert compute_severity("phishing", 0.95, f) == "critical"


def test_high_confidence_without_risk_signal_is_high():
    f = make_features(hostname_length=30, path_length=20)
    assert compute_severity("phishing", 0.80, f) == "high"


def test_low_confidence_phishing_is_medium():
    f = make_features(hostname_length=30, path_length=20)
    assert compute_severity("phishing", 0.55, f) == "medium"

