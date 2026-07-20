"""
features.py — single source of truth for all URL feature extraction.

Both feature_extractor.py (training) and predict.py (inference) import
from this module. This exists specifically to prevent train/inference
feature drift — see the num_dots/num_subdomains www-stripping bug in
v1.1.1 for why this matters: predict.py had silently reimplemented
these functions without the www. fix, causing false positives on any
URL with a www subdomain.

Do not duplicate these functions anywhere else. If you need a new
feature, add it here once and both callers get it automatically.
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse

import pandas as pd
import tldextract


def get_url_length(url):
    if pd.isna(url):
        return 0
    return len(url)


def get_hostname_length(url):
    if pd.isna(url):
        return 0
    try:
        return len(urlparse(url).netloc)
    except Exception:
        return 0


def get_num_subdomains(url):
    """www doesn't count — it's an alias, not a real subdomain."""
    if pd.isna(url):
        return 0
    try:
        subdomain = tldextract.extract(url).subdomain
        parts = [p for p in subdomain.split('.') if p and p.lower() != 'www']
        return len(parts)
    except Exception:
        return 0


def get_num_dots(url):
    """Strip leading www. before counting dots — www is an alias, not signal."""
    if pd.isna(url):
        return 0
    try:
        normalized = re.sub(r'://www\.', '://', url, count=1)
        return normalized.count('.')
    except Exception:
        return url.count('.')


def get_uses_https(url):
    if pd.isna(url):
        return 0
    return 1 if url.startswith('https://') else 0


def get_has_login_keywords(url):
    """login in hostname = suspicious (e.g. login.ru)."""
    if pd.isna(url):
        return 0
    try:
        return 1 if 'login' in urlparse(url).netloc.lower() else 0
    except Exception:
        return 0


def get_has_login_path(url):
    """login in path = usually normal (real auth endpoint like /auth/login)."""
    if pd.isna(url):
        return 0
    try:
        segments = urlparse(url).path.lower().split('/')
        return 1 if any(s in ('login', 'signin', 'sign-in') for s in segments) else 0
    except Exception:
        return 0


def get_hostname_hyphens(url):
    """Hyphens in domain = common brand-spoofing pattern (paypal-secure.com)."""
    if pd.isna(url):
        return 0
    try:
        return urlparse(url).netloc.count('-')
    except Exception:
        return 0


def get_path_hyphens(url):
    """Hyphens in path = usually just an SEO slug, weak signal."""
    if pd.isna(url):
        return 0
    try:
        return urlparse(url).path.count('-')
    except Exception:
        return 0


def get_url_entropy(url):
    if pd.isna(url) or url == '':
        return 0
    try:
        counts = Counter(url)
        total = len(url)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
    except Exception:
        return 0


def get_has_at_symbol(url):
    """http://user@evil.com — browser navigates to evil.com."""
    if pd.isna(url):
        return 0
    return 1 if '@' in url else 0


def get_has_ip_address(url):
    """No legitimate site uses a raw IP as its host."""
    if pd.isna(url):
        return 0
    try:
        hostname = urlparse(url).netloc
        return 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    except Exception:
        return 0


def get_path_length(url):
    if pd.isna(url):
        return 0
    try:
        return len(urlparse(url).path)
    except Exception:
        return 0


def get_num_special_chars(url):
    if pd.isna(url):
        return 0
    return sum(url.count(c) for c in ['%', '=', '?', '&', '#', '+'])


def get_digit_ratio(url):
    if pd.isna(url) or len(url) == 0:
        return 0
    digits = sum(1 for c in url if c.isdigit())
    return round(digits / len(url), 4)


def get_has_port(url):
    if pd.isna(url):
        return 0
    try:
        port = urlparse(url).port
        return 1 if port and port not in (80, 443) else 0
    except Exception:
        return 0


def get_has_suspicious_words(url):
    suspicious = ['secure', 'verify', 'update', 'confirm', 'account',
                  'banking', 'signin', 'webscr', 'ebayisapi', 'paypal']
    if pd.isna(url):
        return 0
    url_lower = url.lower()
    return 1 if any(word in url_lower for word in suspicious) else 0


# Canonical feature name -> function mapping, in a fixed order.
# Both feature_extractor.py and predict.py should build their feature
# dict/columns by iterating FEATURE_FUNCS, so the column order used to
# fit the scaler/model always matches the order used at inference.
FEATURE_FUNCS = {
    'url_length':           get_url_length,
    'hostname_length':      get_hostname_length,
    'num_subdomains':       get_num_subdomains,
    'num_dots':             get_num_dots,
    'uses_https':           get_uses_https,
    'has_login_keywords':   get_has_login_keywords,
    'has_login_path':       get_has_login_path,
    'hostname_hyphens':     get_hostname_hyphens,
    'path_hyphens':         get_path_hyphens,
    'url_entropy':          get_url_entropy,
    'has_at_symbol':        get_has_at_symbol,
    'has_ip_address':       get_has_ip_address,
    'path_length':          get_path_length,
    'num_special_chars':    get_num_special_chars,
    'digit_ratio':          get_digit_ratio,
    'has_port':             get_has_port,
    'has_suspicious_words': get_has_suspicious_words,
}


def extract_features(url: str) -> dict:
    """Single-URL feature extraction for inference (predict.py)."""
    return {name: func(url) for name, func in FEATURE_FUNCS.items()}
