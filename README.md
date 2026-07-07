# 🔍 Phishing URL Detector

A machine learning project that detects phishing URLs using a Random Forest classifier trained on 740,000+ real-world URLs.

---

## Results

| Model | Accuracy | Precision | Recall | F1 Score |
|---|---|---|---|---|
| Logistic Regression | 91.5% | 95.4% | 79.6% | 86.8% |
| **Random Forest** | **96.7%** | **97.3%** | **93.2%** | **95.2%** |

> **Random Forest** was selected as the final model. In phishing detection, **Recall** is the most critical metric — missing a real phishing URL is far more dangerous than a false alarm.

---

## How It Works

```
URL input
   ↓
Whitelist check  →  known trusted domain?  →  ✅ LEGITIMATE
   ↓
Feature extraction  (15 features from the URL structure)
   ↓
StandardScaler  (normalize feature values)
   ↓
Random Forest classifier  (200 decision trees, depth-limited)
   ↓
🚨 PHISHING  or  ✅ LEGITIMATE  +  confidence %
```

---

## Features Extracted

| Feature | Description |
|---|---|
| `url_length` | Total length of the URL |
| `hostname_length` | Length of the domain name |
| `num_subdomains` | Number of subdomains |
| `num_dots` | Number of dots in the URL |
| `uses_https` | Whether the URL uses HTTPS |
| `has_login_keywords` | Presence of "login" in the URL |
| `num_hyphens` | Number of hyphens |
| `url_entropy` | Shannon entropy — high entropy suggests random/obfuscated URLs |
| `has_at_symbol` | Presence of `@` — classic redirect trick |
| `has_ip_address` | Whether the hostname is a raw IP address |
| `path_length` | Length of the URL path after the domain |
| `num_special_chars` | Count of `%`, `=`, `?`, `&`, `#`, `+` |
| `digit_ratio` | Ratio of digits to total characters |
| `has_port` | Presence of a non-standard port (not 80/443) |
| `has_suspicious_words` | Keywords like `verify`, `secure`, `confirm`, `banking` |

---

## Project Structure

```
phishing-url-detector/
│
├── main.py                    # Entry point — CLI (interactive, single URL, batch, JSON)
├── predict.py                 # Prediction pipeline & feature extraction (inference)
├── feature_extractor.py       # Builds the feature dataset from raw CSVs (training)
├── train_model.py             # Trains and evaluates both models
├── download_data.py           # Downloads raw datasets automatically
│
├── rf_phishing_model.pkl      # Trained Random Forest model      (generated, not in repo)
├── lr_phishing_model.pkl      # Trained Logistic Regression model (generated, not in repo)
├── scaler.pkl                 # Fitted StandardScaler             (generated, not in repo)
│
└── Phishing URL dataset/      # Downloaded automatically, not in repo
    ├── PhiUSIIL_Phishing_URL_Dataset.csv
    ├── Phishing URLs.csv
    ├── URL dataset.csv
    └── features_v2.csv        # Extracted features (generated)
```

> **Note:** Dataset files and trained model files are intentionally excluded from this repository due to their size. They are generated locally by following the steps below.

---

## Quickstart

**1 — Clone the repo**
```bash
git clone https://github.com/Dallihunter/Phishing-Website-Detection-by-Machine-Learning.git
cd Phishing-Website-Detection-by-Machine-Learning
```

**2 — Create a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

**3 — Install dependencies**
```bash
pip install -r requirements.txt
```

**4 — Download the datasets**
```bash
python3 download_data.py
```
This downloads and extracts the three raw datasets into `Phishing URL dataset/`.

**5 — Extract features**
```bash
python3 feature_extractor.py
```
This reads the raw CSVs and produces `Phishing URL dataset/features_v2.csv`.

**6 — Train the models**
```bash
python3 train_model.py
```
This trains both models and saves `rf_phishing_model.pkl`, `lr_phishing_model.pkl`, and `scaler.pkl` in the project root.

**7 — Run the detector**

The CLI supports four modes:

```bash
# Interactive mode — type URLs one at a time
python3 main.py

# Check a single URL
python3 main.py --url https://example.com

# Check a single URL, output as JSON (useful for scripts/automation)
python3 main.py --url https://example.com --json

# Batch-check a list of URLs from a file (one URL per line)
python3 main.py --file urls.txt

# Batch-check + JSON output
python3 main.py --file urls.txt --json

# Full usage help
python3 main.py --help
```

**Interactive mode example:**
```
🔍 Phishing URL Detector
Type a URL to check, or 'q' to quit.

Loading model... Ready!

Enter URL: http://paypal-verify.login.ru/secure/account/confirm

─────────────────────────────────────────────
🚨 PHISHING  —  100.0% confidence

  Why:
    • no HTTPS — connection is not encrypted
    • contains suspicious words (verify, secure, confirm...)
    • contains login keyword in URL
─────────────────────────────────────────────
```

**JSON output example:**
```bash
$ python3 main.py --url https://paypal-verify.login.ru/secure --json
```
```json
{
  "url": "http://paypal-verify.login.ru/secure",
  "verdict": "phishing",
  "confidence": 1.0,
  "reasons": [
    "no HTTPS — connection is not encrypted",
    "contains suspicious words (verify, secure, confirm...)"
  ]
}
```
https://github.com/user-attachments/assets/db873665-3a8e-46a0-a8d3-340c920157b1

---

## Dataset

Three public datasets were merged for a total of **740,778 URLs** (480,588 legitimate / 260,190 phishing):

- [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
- Phishing URLs.csv ([Mendeley Data](https://data.mendeley.com))
- URL dataset.csv ([Mendeley Data](https://data.mendeley.com))

All three are downloaded automatically by `download_data.py`.

---

## Dependencies

```
pandas
numpy
scikit-learn
tldextract
joblib
rich
```

Install all at once:
```bash
pip install -r requirements.txt
```

---

## Limitations

- **Short, path-less URLs may be misclassified.** The model was observed to sometimes flag simple, legitimate URLs (e.g. bare domains with short paths, especially with uncommon TLDs like `.ai` or `.ir`) as phishing. This appears to stem from a structural bias in the training data, where phishing samples are often collected as bare landing-page URLs, while legitimate samples tend to include longer paths. This is a known limitation, not a code bug.
- The whitelist covers only 20 well-known domains. Legitimate sites not on the whitelist may occasionally be flagged as phishing.
- The model is trained on URL structure only — it does not fetch or analyze page content.
- Highly obfuscated or newly registered phishing domains may evade detection.

### Roadmap
- **Web API** (FastAPI) to serve predictions over HTTP — foundation for a browser extension and web demo
- **Browser extension** that warns users in real time when visiting a suspected phishing site
- **WHOIS-based domain age feature**: newly registered domains are strongly correlated with phishing, and could help correct the short-URL false-positive bias above
- Investigate and rebalance training data with respect to URL/path length across classes
- Expanded trusted domain whitelist

---

## License

MIT
