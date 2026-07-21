"""
FastAPI service for the phishing URL detector.

Run locally:
    uvicorn app:app --reload

Then test:
    curl -X POST http://127.0.0.1:8000/predict -H "Content-Type: application/json" -d '{"url": "https://example.com"}'
    curl -X POST http://127.0.0.1:8000/v1/detect -H "Content-Type: application/json" -d '{"url": "https://example.com"}'
"""

import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from predict import load_artifacts, classify_url, classify_url_v1


app = FastAPI(
    title="Phishing URL Detector API",
    description="Classifies a URL as phishing or legitimate.",
    version="1.2.0",
)


# Loaded once at startup — NOT per-request. Loading a pickle on every
# request would be slow and wasteful; the model/scaler are stateless
# and safe to share across requests.
model, scaler = load_artifacts()

# 2048 is the de facto safe max URL length (IE's old hard limit, still
# a sane ceiling today) — rejects absurdly long input before it ever
# reaches feature extraction.
MAX_URL_LENGTH = 2048

SCHEMA_VERSION = "1.0"
MODEL_VERSION = "rf-v1.1.1"


class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH, examples=["https://example.com"])


class DetectOptions(BaseModel):
    include_whois: bool = True
    include_visual_similarity: bool = False


class DetectRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH, examples=["https://example.com"])
    options: DetectOptions = DetectOptions()


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


def is_parseable_url(url: str) -> bool:
    """Confirms the string actually resolves to a host after normalization.
    Catches garbage input like 'http://' alone, or strings with malformed
    IPv6 brackets that make urlparse raise ValueError outright."""
    try:
        return bool(urlparse(url).netloc)
    except ValueError:
        return False


# ─────────────────────────────────────────
#  /v1/detect error envelope (API.md section 5)
# ─────────────────────────────────────────

class DetectAPIError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = status_code
        self.code = code
        self.message = message


@app.exception_handler(DetectAPIError)
async def detect_api_error_handler(request, exc: DetectAPIError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "schema_version": SCHEMA_VERSION,
            "error": {"code": exc.code, "message": exc.message},
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}


# ─────────────────────────────────────────
#  Legacy endpoint — unchanged behavior, still used by static/index.html
# ─────────────────────────────────────────

@app.post("/predict")
def predict(payload: URLRequest):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url must not be empty")

    normalized = normalize_url(url)

    if not is_parseable_url(normalized):
        raise HTTPException(
            status_code=400,
            detail="Could not parse a valid domain from this URL",
        )

    try:
        result = classify_url(normalized, model, scaler)
    except Exception:
        # Never leak an internal traceback to an API client — convert
        # any unexpected failure into a clean, generic 400 instead.
        raise HTTPException(status_code=400, detail="Failed to process this URL")

    return result


# ─────────────────────────────────────────
#  v1 SOC-facing endpoint (API.md)
# ─────────────────────────────────────────

@app.post("/v1/detect")
def detect_v1(payload: DetectRequest):
    url = payload.url.strip()
    if not url:
        raise DetectAPIError(400, "INVALID_URL", "url must not be empty")

    normalized = normalize_url(url)

    if not is_parseable_url(normalized):
        raise DetectAPIError(400, "INVALID_URL", "Could not parse a valid domain from this URL")

    if payload.options.include_visual_similarity:
        # Reserved per API.md — not built yet. Fail loudly rather than
        # silently ignoring the flag and returning a result the caller
        # thinks includes visual-similarity signal but doesn't.
        raise DetectAPIError(
            501,
            "NOT_IMPLEMENTED",
            "include_visual_similarity is reserved for a future release and is not yet available",
        )

    try:
        result = classify_url_v1(normalized, model, scaler, include_whois=payload.options.include_whois)
    except Exception:
        raise DetectAPIError(500, "INTERNAL_ERROR", "Unexpected failure while processing this URL")

    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": f"req_{uuid.uuid4().hex[:12]}",
        "url": normalized,
        "verdict": result["verdict"],
        "severity": result["severity"],
        "confidence": result["confidence"],
        "signals": result["signals"],
        "metadata": {
            "domain_age_days": result["domain_age_days"],
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "model_version": MODEL_VERSION,
        },
    }


# serve the frontend at "/" — place index.html in a "static" folder next to app.py
app.mount("/", StaticFiles(directory="static", html=True), name="static")
