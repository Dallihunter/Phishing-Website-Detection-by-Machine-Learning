import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract
import re
from collections import Counter
import math
from whois_lookup import get_domain_age_days, FAILED_LOOKUP_AGE
from features import extract_features
from calibration import apply_domain_age_calibration

# ─────────────────────────────────────────
#  Trusted domains whitelist
# ─────────────────────────────────────────

TRUSTED_DOMAINS = {
    'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'youtube.com', 'wikipedia.org', 'stackoverflow.com', 'reddit.com',
    'instagram.com', 'netflix.com', 'spotify.com', 'dropbox.com',
    'adobe.com', 'cloudflare.com', 'gitlab.com', 'python.org',
}
def get_registrable_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"
    except:
        return ""

def is_trusted_domain(url: str) -> bool:
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        return domain in TRUSTED_DOMAINS
    except:
        return False


# ─────────────────────────────────────────
#  Load models & scaler
# ─────────────────────────────────────────

def load_artifacts():
    rf     = joblib.load('rf_phishing_model.pkl')
    scaler = joblib.load('scaler.pkl')
    return rf, scaler



# ─────────────────────────────────────────
#  Explain why a URL looks suspicious
# ─────────────────────────────────────────

def explain(features: dict) -> list:
    reasons = []

    if features['has_ip_address']:
        reasons.append("uses raw IP address instead of domain name")
    if features['has_at_symbol']:
        reasons.append("contains @ symbol — classic redirect trick")
    if features['uses_https'] == 0:
        reasons.append("no HTTPS — connection is not encrypted")
    if features['has_suspicious_words']:
        reasons.append("contains suspicious words (verify, secure, confirm...)")
    if features['has_login_keywords']:
        reasons.append("login appears in the domain name — spoofing pattern")
    if features['num_subdomains'] >= 3:
        reasons.append(f"too many subdomains ({features['num_subdomains']})")
    if features['url_length'] > 100:
        reasons.append(f"unusually long URL ({features['url_length']} chars)")
    if features['url_entropy'] > 4.8:
        reasons.append(f"high entropy — URL looks randomly generated ({features['url_entropy']:.2f})")
    if features['has_port']:
        reasons.append("uses non-standard port")
    if features['num_special_chars'] > 5:
        reasons.append(f"many special characters ({features['num_special_chars']})")
    if features['hostname_hyphens'] >= 2:
        reasons.append(f"multiple hyphens in domain — possible brand spoofing")

    return reasons


# ─────────────────────────────────────────
#  Main predict function
# ─────────────────────────────────────────

def predict(url: str, model, scaler) -> None:
    border = "=" * 55
    print(f"\n{border}")
    print(f"  URL : {url}")

    # check whitelist first
    if is_trusted_domain(url):
        print(f"  Result      : ✅ LEGITIMATE")
        print(f"  Reason      : domain is in trusted whitelist")
        print(border)
        return

    # extract features
    features = extract_features(url)
    X        = pd.DataFrame([features])
    X_scaled = scaler.transform(X)

    # predict
    prediction   = model.predict(X_scaled)[0]
    confidence   = model.predict_proba(X_scaled)[0]
    phishing_pct = round(confidence[1] * 100, 1)
    legit_pct    = round(confidence[0] * 100, 1)

    label = "🚨 PHISHING" if prediction == 1 else "✅ LEGITIMATE"
    print(f"  Result      : {label}")
    print(f"  Confidence  : Phishing {phishing_pct}%  |  Legitimate {legit_pct}%")

    if prediction == 1:
        reasons = explain(features)
        if reasons:
            print(f"\n  Why suspicious:")
            for r in reasons:
                print(f"    • {r}")

    print(f"\n  Features:")
    for k, v in features.items():
        print(f"    {k:<25} {v}")
    print(border)

def classify_url(url: str, model, scaler) -> dict:
    if is_trusted_domain(url):
        return {
            "url": url,
            "verdict": "legitimate",
            "confidence": 1.0,
            "reasons": ["trusted domain (whitelist)"],
        }

    features = extract_features(url)
    X = pd.DataFrame([features])
    X_scaled = scaler.transform(X)

    raw_confidence = model.predict_proba(X_scaled)[0]
    raw_phishing_prob = float(raw_confidence[1])

    domain = get_registrable_domain(url)
    age_days = get_domain_age_days(domain) if domain else FAILED_LOOKUP_AGE

    phishing_prob, was_calibrated = apply_domain_age_calibration(raw_phishing_prob, age_days)

    verdict = "phishing" if phishing_prob >= 0.5 else "legitimate"
    confidence_pct = round(phishing_prob if verdict == "phishing" else 1 - phishing_prob, 4)
    reasons = explain(features) if verdict == "phishing" else []

    if was_calibrated and verdict == "phishing":
        reasons.append(
            f"long-established domain (~{age_days} days) partially offset the model's "
            f"raw score ({round(raw_phishing_prob * 100, 1)}% \u2192 {round(phishing_prob * 100, 1)}%)"
        )
    elif age_days != FAILED_LOOKUP_AGE and age_days < 180 and verdict == "phishing":
        reasons.append(f"domain registered recently (~{age_days} days ago)")

    return {
        "url": url,
        "verdict": verdict,
        "confidence": confidence_pct,
        "reasons": reasons,
        "domain_age_days": age_days,
    }

# ─────────────────────────────────────────
#  Run
# ─────────────────────────────────────────

if __name__ == '__main__':
    print("Loading models...")
    model, scaler = load_artifacts()
    print("Ready!")

    test_urls = [
        # legitimate
        "https://www.google.com",
        "https://github.com/user/repo",
        "https://stackoverflow.com/questions/123",
        # phishing
        "http://paypal-verify.login.ru/secure/account/confirm",
        "http://192.168.1.1/login",
        "http://www.amazon.com@malicious-site.com/update",
        "https://secure-banking-verify.suspicious-domain.tk/signin",
    ]

    for url in test_urls:
        predict(url, model, scaler)
