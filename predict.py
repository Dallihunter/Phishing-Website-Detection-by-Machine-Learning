import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract
import re
from collections import Counter
import math


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
#  Feature extraction (same as training)
# ─────────────────────────────────────────

def extract_features(url: str) -> dict:
    def url_length(u):
        return len(u)

    def hostname_length(u):
        try: return len(urlparse(u).netloc)
        except: return 0

    def num_subdomains(u):
        try:
            sub = tldextract.extract(u).subdomain
            return 0 if sub == '' else sub.count('.') + 1
        except: return 0

    def num_dots(u):
        return u.count('.')

    def uses_https(u):
        return 1 if u.startswith('https://') else 0

    def has_login_keywords(u):
        return 1 if 'login' in u.lower() else 0

    def num_hyphens(u):
        return u.count('-')

    def url_entropy(u):
        if u == '': return 0
        counts = Counter(u)
        total  = len(u)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())

    def has_at_symbol(u):
        return 1 if '@' in u else 0

    def has_ip_address(u):
        try:
            hostname = urlparse(u).netloc
            return 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
        except: return 0

    def path_length(u):
        try: return len(urlparse(u).path)
        except: return 0

    def num_special_chars(u):
        return sum(u.count(c) for c in ['%', '=', '?', '&', '#', '+'])

    def digit_ratio(u):
        if len(u) == 0: return 0
        return round(sum(1 for c in u if c.isdigit()) / len(u), 4)

    def has_port(u):
        try:
            port = urlparse(u).port
            return 1 if port and port not in (80, 443) else 0
        except: return 0

    def has_suspicious_words(u):
        words = ['secure', 'verify', 'update', 'confirm', 'account',
                 'banking', 'signin', 'webscr', 'ebayisapi', 'paypal']
        return 1 if any(w in u.lower() for w in words) else 0

    return {
        'url_length':           url_length(url),
        'hostname_length':      hostname_length(url),
        'num_subdomains':       num_subdomains(url),
        'num_dots':             num_dots(url),
        'uses_https':           uses_https(url),
        'has_login_keywords':   has_login_keywords(url),
        'num_hyphens':          num_hyphens(url),
        'url_entropy':          url_entropy(url),
        'has_at_symbol':        has_at_symbol(url),
        'has_ip_address':       has_ip_address(url),
        'path_length':          path_length(url),
        'num_special_chars':    num_special_chars(url),
        'digit_ratio':          digit_ratio(url),
        'has_port':             has_port(url),
        'has_suspicious_words': has_suspicious_words(url),
    }


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
        reasons.append("contains login keyword in URL")
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
