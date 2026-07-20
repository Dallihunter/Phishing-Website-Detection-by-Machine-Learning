"""
calibration.py — post-model risk calibration layer.

The Random Forest in rf_phishing_model.pkl only ever sees URL
structure. This module blends its raw prediction with signals that
live outside the trained feature set — starting with WHOIS domain
age — without retraining and without becoming a whitelist-style
override.

Design constraints (read before changing the constants below):

1. NEVER a hard override. Domain age only nudges the phishing
   probability by a bounded amount in logit space. It cannot, by
   itself, force a verdict either direction.

2. Recall-protective by construction. If the model's raw phishing
   probability is already >= CONFIDENT_PHISHING_PROB, calibration is
   skipped entirely. A long-established domain that's been
   compromised (or spoofed via URL tricks) and shows strong
   independent signals (has_at_symbol, has_ip_address, etc.) still
   gets flagged — old age alone cannot erase a confident detection.

3. Asymmetric on purpose. This layer only meaningfully *helps*
   well-established domains; it does not meaningfully *hurt* young
   ones (a brand-new domain's age_score sits near 0, which produces a
   roughly neutral age_phishing_prob near 0.5 — not a push toward
   "phishing"). The existing "domain registered recently" text reason
   in predict.py already communicates young-domain risk; this module
   is deliberately one-sided so it doesn't double up and start
   punishing new legitimate businesses on top of that.

4. Unknown age = no adjustment. WHOIS fails often for ccTLDs and
   privacy-protected domains (see the .ir case in your own testing).
   When age is unknown, this returns the raw probability unchanged —
   it never guesses.

TUNING NOTE: AGE_WEIGHT below is a starting hyperparameter, not a
finalized constant. Before trusting it in production:
  - run tests/test_model_evaluation.py and confirm accuracy/recall
    floors still hold (calibration only touches predict.py's
    classify_url path, not model.predict() directly, so these should
    be unaffected — but verify after any change here)
  - run tests/test_calibration.py (deterministic, no network)
  - keep a running log of real cases where calibration flips a
    verdict, and periodically sanity-check that log by hand
"""

import math

from whois_lookup import FAILED_LOOKUP_AGE

# ── tunable parameters ────────────────────────────────────────────────

AGE_WEIGHT = 0.4                  # weight given to the age prior vs. the model's own logit
AGE_FULL_TRUST_DAYS = 730         # age (days) at which the age prior reaches max strength (~2 years)
AGE_PRIOR_LEGIT_CEILING = 0.95    # age alone can imply at most 95% legitimacy — never certainty
CONFIDENT_PHISHING_PROB = 0.95    # at/above this, the model's raw signal is trusted as-is; no adjustment


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)  # avoid log(0) / log(inf) at the extremes
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def apply_domain_age_calibration(phishing_prob: float, age_days) -> tuple:
    """
    Blends the model's raw phishing probability with a domain-age
    prior in logit space.

    Returns (adjusted_phishing_prob, was_adjusted). was_adjusted is
    False whenever age is unknown (WHOIS failed) or the model's own
    signal was already confident enough to skip calibration — in both
    cases the original probability is returned unchanged.
    """
    if age_days is None or age_days == FAILED_LOOKUP_AGE:
        return phishing_prob, False

    if phishing_prob >= CONFIDENT_PHISHING_PROB:
        return phishing_prob, False

    age_score = min(age_days / AGE_FULL_TRUST_DAYS, 1.0)
    age_legit_prob = 0.5 + (AGE_PRIOR_LEGIT_CEILING - 0.5) * age_score
    age_phishing_prob = 1 - age_legit_prob

    model_logit = _logit(phishing_prob)
    age_logit = _logit(age_phishing_prob)
    blended_logit = (1 - AGE_WEIGHT) * model_logit + AGE_WEIGHT * age_logit

    return _sigmoid(blended_logit), True
