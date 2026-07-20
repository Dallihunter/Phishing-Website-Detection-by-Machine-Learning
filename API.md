# Detection API Schema Draft — SOC/SIEM-Compatible

Status: draft for review. Goal: make the response shape something a SOC engineer
can wire into Splunk/Sentinel/SOAR with minimal glue code, without you having to
build a dashboard.

---

## 1. Design principles

- **Stable, versioned schema.** Consumers automate against this — breaking it
  breaks their pipelines silently. Version it from day one.
- **Severity, not just a raw probability.** SOC tooling triages on severity
  tiers (routing to auto-block / analyst queue / log-only), not on a bare
  0.87 float.
- **Always explain.** Consistent with your existing `explain()` philosophy —
  every non-clean verdict carries the signals that fired.
- **Cheap by default, expensive by request.** Structural URL analysis is fast;
  WHOIS and visual-similarity are slower and costlier, so they're opt-in flags,
  not automatic.

---

## 2. `POST /v1/detect` — synchronous single-URL check

### Request

```json
{
  "url": "http://paypal-verify.login.ru/secure/account/confirm",
  "options": {
    "include_whois": true,
    "include_visual_similarity": false
  }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `url` | string | yes | max 2048 chars, matches current `app.py` limit |
| `options.include_whois` | bool | no, default `true` | adds domain-age lookup (slower, network call) |
| `options.include_visual_similarity` | bool | no, default `false` | premium tier; headless-browser render, expensive |

### Response

```json
{
  "schema_version": "1.0",
  "request_id": "req_9f3a2b1c",
  "url": "http://paypal-verify.login.ru/secure/account/confirm",
  "verdict": "malicious",
  "severity": "high",
  "confidence": 0.94,
  "signals": [
    {
      "code": "SUSPICIOUS_KEYWORDS",
      "description": "contains suspicious words (verify, secure, confirm)"
    },
    {
      "code": "LOGIN_IN_HOSTNAME",
      "description": "login appears in the domain name — spoofing pattern"
    },
    {
      "code": "NO_HTTPS",
      "description": "no HTTPS — connection is not encrypted"
    },
    {
      "code": "DOMAIN_RECENTLY_REGISTERED",
      "description": "domain registered ~42 days ago"
    }
  ],
  "metadata": {
    "domain_age_days": 42,
    "checked_at": "2026-07-20T14:03:11Z",
    "model_version": "rf-v1.1.1"
  }
}
```

### Severity tiers

Maps directly to your planned tiered alerting (auto-alert / human review /
log-only), so the API just hands the SOC a pre-sorted verdict:

| `severity` | Meaning | Typical SOC action |
|---|---|---|
| `critical` | Very high confidence phishing + high-risk signal (IP address, `@` redirect, active brand impersonation) | Auto-block via WAF/CSP |
| `high` | High confidence phishing | Auto-alert, fast-track review |
| `medium` | Suspicious but uncertain (e.g. short bare-domain edge case) | Analyst queue |
| `low` | Weak signals only | Log-only |
| `clean` | Legitimate / whitelisted | No action |

### Signal codes

Stable enum strings (not free-text) so SOAR playbooks can branch on them
without string-matching your human-readable reasons. Human-readable
`description` stays for analysts; `code` is for automation. Suggested initial
set, derived from your existing `explain()` reasons:

```
HAS_IP_ADDRESS
HAS_AT_SYMBOL
NO_HTTPS
SUSPICIOUS_KEYWORDS
LOGIN_IN_HOSTNAME
EXCESSIVE_SUBDOMAINS
LONG_URL
HIGH_ENTROPY
NONSTANDARD_PORT
EXCESSIVE_SPECIAL_CHARS
HOSTNAME_HYPHENS
DOMAIN_RECENTLY_REGISTERED
DOMAIN_AGE_UNKNOWN
VISUAL_BRAND_MATCH        (reserved — visual-similarity module, not yet built)
WHITELISTED_DOMAIN
```

---

## 3. `POST /v1/detect/batch` — high-volume

Infrastructure buyers think in volume, so batch needs to exist from day one,
not bolted on later.

```json
{
  "urls": ["https://a.com", "http://b-secure-verify.tk"]
}
```

```json
{
  "schema_version": "1.0",
  "batch_id": "batch_71ac",
  "results": [ { "...": "same shape as single /detect result" } ]
}
```

---

## 4. Webhook payload (async / subscription mode)

For customers who register a callback instead of polling — same envelope as
the synchronous response, plus delivery metadata:

```json
{
  "event": "detection.completed",
  "schema_version": "1.0",
  "delivered_at": "2026-07-20T14:03:12Z",
  "data": {
    "...": "same object as the /v1/detect response body"
  }
}
```

Delivery basics to spec later, not now: HMAC signature header for payload
verification, retry-with-backoff, and a `event` enum so the same endpoint can
later carry `detection.completed`, `detection.failed`, `model.updated`, etc.

---

## 5. Error responses

Kept generic on purpose — matches the existing `app.py` behavior of never
leaking internal tracebacks.

```json
{
  "schema_version": "1.0",
  "error": {
    "code": "INVALID_URL",
    "message": "Could not parse a valid domain from this URL"
  }
}
```

| `code` | HTTP status | Cause |
|---|---|---|
| `INVALID_URL` | 400 | unparseable / empty |
| `RATE_LIMITED` | 429 | over plan quota |
| `UNAUTHORIZED` | 401 | missing/invalid API key |
| `INTERNAL_ERROR` | 500 | unexpected failure |

---

## 6. Open questions before finalizing

1. **STIX/TAXII support** — worth it for enterprise SOC buyers, but real work.
   Decide if v1 ships plain JSON only and STIX comes later as a paid-tier
   export format.
2. **Confidence vs. severity precedence** — should a `medium` severity ever
   override a high raw confidence score (e.g. the known short-bare-domain
   bias case)? Recommend yes — severity should factor in known model
   weaknesses, not just raw `predict_proba`.
3. **Versioning strategy** — path-based (`/v1/`, `/v2/`) vs. header-based.
   Path-based is simpler for SOC engineers to reason about; recommend that.
4. **`domain_age_days: -1` (failed WHOIS lookup)** — should this surface as
   its own signal code (`DOMAIN_AGE_UNKNOWN`) rather than a bare `-1` in
   metadata, so automation doesn't misinterpret it as "very new domain."
   Recommend yes — this is a currently-latent bug risk if `-1` ever gets
   compared numerically downstream.
