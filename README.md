# 🔍 Phishing URL Detector
 
A machine learning project that detects phishing URLs using a Random Forest classifier trained on 740,000+ real-world URLs.
 
---
 
## Results
 
| Model | Accuracy | Precision | Recall | F1 Score |
|---|---|---|---|---|
| Logistic Regression | 91.5% | 95.4% | 79.6% | 86.8% |
| **Random Forest** | **96.7%** | **97.3%** | **93.2%** | **95.2%** |
 
> **Random Forest** was selected as the final model. In phishing detection, **Recall** is the most critical metric — missing a real phishing URL is far more dangerous than a false alarm. The Random Forest missed only 3,514 phishing URLs vs 10,614 for Logistic Regression.
 
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
Random Forest classifier  (200 decision trees)
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
├── main.py                  # Entry point — interactive URL checker
├── predict.py               # Prediction pipeline & feature extraction
├── feature_extractor.py     # Builds the feature dataset from raw CSVs
├── train_model.py           # Trains and evaluates both models
├── preprocessing.py         # Data cleaning utility
│
├── rf_phishing_model.pkl    # Trained Random Forest model
├── lr_phishing_model.pkl    # Trained Logistic Regression model
├── scaler.pkl               # Fitted StandardScaler
│
└── Phishing URL dataset/
    ├── PhiUSIIL_Phishing_URL_Dataset.csv
    ├── Phishing URLs.csv
    ├── URL dataset.csv
    └── features_v2.csv      # Extracted features (generated)
```
 
---
 
## Quickstart
 
**1 — Clone the repo**
```bash
git clone https://github.com/yourusername/phishing-url-detector.git
cd phishing-url-detector
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
 
**4 — Run the detector**
```bash
python3 main.py
```
 
```
🔍 Phishing URL Detector
Type a URL to check, or 'q' to quit.
 
Loading model... Ready!
 
Enter URL: http://paypal-verify.login.ru/secure/account/confirm
 
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🚨  PHISHING  —  100.0% confidence
 
  Why:
    • no HTTPS — connection is not encrypted
    • contains suspicious words (verify, secure, confirm...)
    • contains login keyword in URL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
 
---
 
## Retrain the Model
 
If you want to retrain from scratch using the raw datasets:
 
```bash
# Step 1 — Extract features from raw CSVs
python3 feature_extractor.py
 
# Step 2 — Train both models
python3 train_model.py
```
 
---
 
## Dataset
 
Three public datasets were merged for a total of **740,778 URLs** (480,588 legitimate / 260,190 phishing):
 
- [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
- Phishing URLs.csv
- URL dataset.csv
---
 
## Dependencies
 
```
pandas
numpy
scikit-learn
tldextract
joblib
```
 
Install all at once:
```bash
pip install pandas numpy scikit-learn tldextract joblib
```
 
---
 
## Limitations
 
- The whitelist covers only 20 well-known domains. Legitimate sites not on the whitelist may occasionally be flagged as phishing.
- The model is trained on URL structure only — it does not fetch or analyze page content.
- Highly obfuscated or newly registered phishing domains may evade detection.
---
 
## License
 
MIT
