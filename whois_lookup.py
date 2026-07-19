"""
WHOIS-based domain age lookup.

Standalone module — test this on its own before wiring it into
predict.py / feature_extractor.py.

Usage:
    python3 whois_lookup.py example.com paypal-verify.login.ru
"""

import socket
import sys
from datetime import datetime, timezone

import whois  # pip install python-whois

TIMEOUT_SECONDS = 4
FAILED_LOOKUP_AGE = -1  # sentinel value when we can't determine age


def get_domain_creation_date(domain: str):
    """
    Returns a timezone-aware datetime of domain registration, or None
    if the lookup fails, times out, or the WHOIS record has no
    creation date (common for some ccTLDs / privacy-protected domains).
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(TIMEOUT_SECONDS)
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        # some registrars return a list of dates (rare, but happens)
        if isinstance(creation, list):
            creation = creation[0] if creation else None

        if creation is None:
            return None

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        return creation

    except Exception:
        # covers: socket.timeout, WHOIS server refusal, parsing errors,
        # unregistered domains, etc. — never let this crash the pipeline
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def get_domain_age_days(domain: str) -> int:
    """
    Returns domain age in days, or FAILED_LOOKUP_AGE (-1) if unknown.
    -1 is used instead of 0 so the model can distinguish
    "lookup failed" from "registered today" (both are informative,
    but for different reasons).
    """
    creation = get_domain_creation_date(domain)
    if creation is None:
        return FAILED_LOOKUP_AGE

    now = datetime.now(timezone.utc)
    age = (now - creation).days
    return max(age, 0)


if __name__ == "__main__":
    domains = sys.argv[1:] or ["google.com", "github.com", "python.org"]

    for d in domains:
        age = get_domain_age_days(d)
        if age == FAILED_LOOKUP_AGE:
            print(f"  {d:<30} lookup failed / no creation date")
        else:
            years = age / 365
            print(f"  {d:<30} {age:>6} days  (~{years:.1f} years)")
