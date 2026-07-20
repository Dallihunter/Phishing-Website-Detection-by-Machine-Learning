"""
Unit tests for calibration.py. Fully deterministic — no network calls,
no model/scaler needed, so these always run regardless of whether
you've trained anything.
"""

import pytest
from calibration import apply_domain_age_calibration, CONFIDENT_PHISHING_PROB
from whois_lookup import FAILED_LOOKUP_AGE


def test_unknown_age_is_never_adjusted():
    prob, was_adjusted = apply_domain_age_calibration(0.87, FAILED_LOOKUP_AGE)
    assert was_adjusted is False
    assert prob == 0.87


def test_none_age_is_never_adjusted():
    prob, was_adjusted = apply_domain_age_calibration(0.87, None)
    assert was_adjusted is False
    assert prob == 0.87


def test_very_confident_model_score_is_never_adjusted():
    """Strong independent evidence (e.g. IP address, @ symbol) must not
    be overridden just because a domain happens to be old — protects
    recall on compromised/spoofed-but-aged domains."""
    prob, was_adjusted = apply_domain_age_calibration(0.99, age_days=10000)
    assert was_adjusted is False
    assert prob == 0.99


def test_old_domain_reduces_borderline_phishing_score():
    """The torob.com regression case: a borderline-high score on a
    genuinely old domain should be pulled down."""
    raw_prob = 0.8695
    adjusted, was_adjusted = apply_domain_age_calibration(raw_prob, age_days=7863)
    assert was_adjusted is True
    assert adjusted < raw_prob


def test_brand_new_domain_is_roughly_neutral_not_punished():
    """
    A 1-day-old domain should NOT get pushed meaningfully further
    toward phishing by this layer -- age-based suspicion is handled
    separately (see the "domain registered recently" text reason in
    predict.py), so this layer should stay close to neutral here.
    """
    raw_prob = 0.6
    adjusted, was_adjusted = apply_domain_age_calibration(raw_prob, age_days=1)
    assert was_adjusted is True
    # neutral means "close to unchanged", not "identical" -- allow
    # a small tolerance rather than asserting exact equality
    assert abs(adjusted - raw_prob) < 0.05


def test_calibration_is_monotonic_in_age():
    """Older domains should never end up with a HIGHER phishing
    probability than younger domains, all else equal."""
    raw_prob = 0.7
    young, _ = apply_domain_age_calibration(raw_prob, age_days=30)
    old, _ = apply_domain_age_calibration(raw_prob, age_days=3650)
    assert old <= young


def test_age_beyond_full_trust_days_does_not_keep_helping():
    """Age score should saturate -- a 5-year-old domain and a
    20-year-old domain get the same treatment, since AGE_FULL_TRUST_DAYS
    caps the effect."""
    raw_prob = 0.7
    five_years, _ = apply_domain_age_calibration(raw_prob, age_days=365 * 5)
    twenty_years, _ = apply_domain_age_calibration(raw_prob, age_days=365 * 20)
    assert five_years == pytest.approx(twenty_years, abs=1e-9)


def test_adjusted_prob_stays_in_valid_range():
    for raw_prob in [0.5, 0.6, 0.75, 0.9, 0.949]:
        for age in [0, 1, 100, 730, 5000]:
            adjusted, _ = apply_domain_age_calibration(raw_prob, age)
            assert 0.0 <= adjusted <= 1.0

