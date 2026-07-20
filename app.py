"""
FastAPI service for the phishing URL detector.

Run locally:
    uvicorn app:app --reload

Then test:
    curl -X POST http://127.0.0.1:8000/predict -H "Content-Type: application/json" -d '{"url": "https://example.com"}'
"""


from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from predict import load_artifacts, classify_url
from fastapi.staticfiles import StaticFiles




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


class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH, examples=["https://example.com"])


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


@app.get("/health")
def health():
    return {"status": "ok"}


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

# serve the frontend at "/" — place index.html in a "static" folder next to app.py
app.mount("/", StaticFiles(directory="static", html=True), name="static")
