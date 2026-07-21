"""
signals.py — stable signal codes + severity tiers for the v1 API.

`explain()` in predict.py returns human-readable strings for the CLI
and the legacy /predict endpoint. SOC/SOAR automation (per API.md)
needs the same information as a stable enum-style `code`, so
playbooks can branch on it without string-matching free text.

This module derives both codes and severity from the exact same
`features` dict explain() uses, so the two never drift out of sync —
same failure mode this project already fixed once for num_dots /
num_subdomains, so we're not reintroducing it here.

Codes implemented match the list in API.md, plus one addition:
DOMAIN_AGE_OFFSET_APPLIED. API.md's original code list only covered
the "recently registered" young-domain case; it had no code for the
opposite case calibration.py already handles (an old domain pulling a
borderline score down). This is a genuine gap in the draft, not a
deviation from it — flagged so API.md can be updated to match.
"""

from whois_lookup import FAILED_LOOKUP_AGE

# ── known-weakness override (README "Limitations" section) ──────────
# Short hostnames with little/no path are the documented residual bias
# — the RF's decision boundary is unstable here due to training-data
# composition, not a feature bug. Severity is capped at "medium" in
# this zone regardless of raw confidence, per API.md open question #2.
SHORT_BARE_DOMAIN_HOSTNAME_MAX = 15
SHORT_BARE_DOMAIN_PATH_MAX = 3

# thresholds for the non-edge-case severity ladder
CRITICAL_PHISHING_PROB = 0.90
HIGH_PHISHING_PROB = 0.75


def is_short_bare_domain_edge_case(features: dict) -> bool:
    """True if this URL falls in the documented short-bare-domain
    bias window — a known model weakness, not a fresh detection."""
    return (
        features["hostname_length"] <= SHORT_BARE_DOMAIN_HOSTNAME_MAX
        and features["path_length"] <= SHORT_BARE_DOMAIN_PATH_MAX
    )


def get_structured_signals(
    features: dict,
    age_days=None,
    was_calibrated: bool = False,
    raw_phishing_prob: float = None,
    phishing_prob: float = None,
) -> list:
    """Returns [{"code": ..., "description": ...}, ...] for every
    signal that fired. `age_days=None` means WHOIS wasn't requested
    (options.include_whois=false) — no domain-age signal is emitted,
    distinct from age_days == FAILED_LOOKUP_AGE (lookup was attempted
    and failed), which surfaces as DOMAIN_AGE_UNKNOWN rather than a
    bare -1 that automation could misread as "brand new"."""
    signals = []

    if features["has_ip_address"]:
        signals.append({
            "code": "HAS_IP_ADDRESS",
            "description": "uses raw IP address instead of domain name",
        })
    if features["has_at_symbol"]:
        signals.append({
            "code": "HAS_AT_SYMBOL",
            "description": "contains @ symbol — classic redirect trick",
        })
    if features["uses_https"] == 0:
        signals.append({
            "code": "NO_HTTPS",
            "description": "no HTTPS — connection is not encrypted",
        })
    if features["has_suspicious_words"]:
        signals.append({
            "code": "SUSPICIOUS_KEYWORDS",
            "description": "contains suspicious words (verify, secure, confirm...)",
        })
    if features["has_login_keywords"]:
        signals.append({
            "code": "LOGIN_IN_HOSTNAME",
            "description": "login appears in the domain name — spoofing pattern",
        })
    if features["num_subdomains"] >= 3:
        signals.append({
            "code": "EXCESSIVE_SUBDOMAINS",
            "description": f"too many subdomains ({features['num_subdomains']})",
        })
    if features["url_length"] > 100:
        signals.append({
            "code": "LONG_URL",
            "description": f"unusually long URL ({features['url_length']} chars)",
        })
    if features["url_entropy"] > 4.8:
        signals.append({
            "code": "HIGH_ENTROPY",
            "description": f"high entropy — URL looks randomly generated ({features['url_entropy']:.2f})",
        })
    if features["has_port"]:
        signals.append({
            "code": "NONSTANDARD_PORT",
            "description": "uses non-standard port",
        })
    if features["num_special_chars"] > 5:
        signals.append({
            "code": "EXCESSIVE_SPECIAL_CHARS",
            "description": f"many special characters ({features['num_special_chars']})",
        })
    if features["hostname_hyphens"] >= 2:
        signals.append({
            "code": "HOSTNAME_HYPHENS",
            "description": "multiple hyphens in domain — possible brand spoofing",
        })

    # domain-age signals — only if WHOIS was actually requested
    if age_days is not None:
        if age_days == FAILED_LOOKUP_AGE:
            signals.append({
                "code": "DOMAIN_AGE_UNKNOWN",
                "description": "WHOIS lookup failed or domain has no creation date on record",
            })
        elif was_calibrated and raw_phishing_prob is not None and phishing_prob is not None:
            signals.append({
                "code": "DOMAIN_AGE_OFFSET_APPLIED",
                "description": (
                    f"long-established domain (~{age_days} days) partially offset the "
                    f"model's raw score ({round(raw_phishing_prob * 100, 1)}% "
                    f"\u2192 {round(phishing_prob * 100, 1)}%)"
                ),
            })
        elif age_days < 180:
            signals.append({
                "code": "DOMAIN_RECENTLY_REGISTERED",
                "description": f"domain registered recently (~{age_days} days ago)",
            })

    return signals


def compute_severity(verdict: str, phishing_prob: float, features: dict) -> str:
    """
    verdict: "phishing" | "legitimate" (the model's binary call)
    Returns one of: critical, high, medium, low, clean.

    Per API.md open question #2: severity factors in known model
    weaknesses rather than trusting raw confidence alone. The
    short-bare-domain edge case is capped at "medium" even when
    phishing_prob is high, since that's a documented bias, not a
    confident detection.
    """
    if verdict == "legitimate":
        has_weak_signal = any([
            features["has_ip_address"],
            features["has_at_symbol"],
            features["uses_https"] == 0,
            features["has_suspicious_words"],
            features["has_login_keywords"],
            features["hostname_hyphens"] >= 2,
        ])
        return "low" if has_weak_signal else "clean"

    # verdict == "phishing" from here
    if is_short_bare_domain_edge_case(features):
        return "medium"

    high_risk_signal = features["has_ip_address"] or features["has_at_symbol"]

    if phishing_prob >= CRITICAL_PHISHING_PROB and high_risk_signal:
        return "critical"
    if phishing_prob >= HIGH_PHISHING_PROB:
        return "high"
    return "medium"
