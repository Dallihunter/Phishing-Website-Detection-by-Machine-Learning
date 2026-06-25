import pandas as pd
from urllib.parse import urlparse
import tldextract
import re
from collections import Counter
import math


# ─────────────────────────────────────────
#  Load & merge the three datasets
# ─────────────────────────────────────────

def load_datasets():
    # Dataset 1
    df1 = pd.read_csv('Phishing URL dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
    df1 = df1.drop(columns=[
        'Domain','URLLength','FILENAME', 'DomainLength', 'IsDomainIP', 'TLD',
        'URLSimilarityIndex', 'CharContinuationRate', 'TLDLegitimateProb',
        'URLCharProb', 'TLDLength', 'NoOfSubDomain', 'HasObfuscation',
        'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL',
        'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
        'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
        'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS',
        'LineOfCode', 'LargestLineLength', 'HasTitle', 'Title',
        'DomainTitleMatchScore', 'URLTitleMatchScore', 'HasFavicon', 'Robots',
        'IsResponsive', 'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription',
        'NoOfPopup', 'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet',
        'HasSubmitButton', 'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay',
        'Crypto', 'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS',
        'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
    ])
    # در این دیتاست label=1 یعنی legitimate، پس برعکس می‌کنیم
    df1['label'] = df1['label'].apply(lambda x: 0 if x == 1 else 1)
    df1 = df1.rename(columns={'URL': 'url'})

    # Dataset 2
    df2 = pd.read_csv('Phishing URL dataset/Phishing URLs.csv')
    df2['label'] = df2['Type'].apply(lambda x: 1 if x == 'Phishing' else 0)
    df2 = df2.drop(columns='Type')

    # Dataset 3
    df3 = pd.read_csv('Phishing URL dataset/URL dataset.csv')
    df3['label'] = df3['type'].apply(lambda x: 1 if x == 'phishing' else 0)
    df3 = df3.drop(columns='type')

    return pd.concat([df1, df2, df3], ignore_index=True)


# ─────────────────────────────────────────
#  Feature functions — existing
# ─────────────────────────────────────────

def get_url_length(url):
    if pd.isna(url):
        return 0
    return len(url)


def get_hostname_length(url):
    if pd.isna(url):
        return 0
    try:
        return len(urlparse(url).netloc)
    except:
        return 0


def get_num_subdomains(url):
    if pd.isna(url):
        return 0
    try:
        subdomain = tldextract.extract(url).subdomain
        return 0 if subdomain == '' else subdomain.count('.') + 1
    except:
        return 0


def get_num_dots(url):
    if pd.isna(url):
        return 0
    return url.count('.')


def get_uses_https(url):
    if pd.isna(url):
        return 0
    return 1 if url.startswith('https://') else 0


def get_has_login_keywords(url):
    if pd.isna(url):
        return 0
    return 1 if 'login' in url.lower() else 0


def get_num_hyphens(url):
    if pd.isna(url):
        return 0
    return url.count('-')


def get_url_entropy(url):
    if pd.isna(url) or url == '':
        return 0
    try:
        counts = Counter(url)
        total = len(url)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
    except:
        return 0


# ─────────────────────────────────────────
#  Feature functions — new
# ─────────────────────────────────────────

def get_path_length(url):
    """طول path بعد از domain — فیشینگ‌ها معمولاً path طولانی‌تری دارن"""
    if pd.isna(url):
        return 0
    try:
        return len(urlparse(url).path)
    except:
        return 0


def get_num_special_chars(url):
    """تعداد کاراکترهای خاص در URL مثل %, =, ?, & — نشانه پیچیدگی مصنوعی"""
    if pd.isna(url):
        return 0
    return sum(url.count(c) for c in ['%', '=', '?', '&', '#', '+'])


def get_digit_ratio(url):
    """نسبت اعداد به کل کاراکترهای URL — فیشینگ‌ها عدد بیشتری دارن"""
    if pd.isna(url) or len(url) == 0:
        return 0
    digits = sum(1 for c in url if c.isdigit())
    return round(digits / len(url), 4)


def get_has_port(url):
    """آیا URL یه port غیراستاندارد داره مثل :8080، :8443 — نشانه مشکوک"""
    if pd.isna(url):
        return 0
    try:
        port = urlparse(url).port
        return 1 if port and port not in (80, 443) else 0
    except:
        return 0


def get_has_suspicious_words(url):
    """کلمات مشکوک رایج در URL های فیشینگ"""
    if pd.isna(url):
        return 0
    suspicious = ['secure', 'verify', 'update', 'confirm', 'account',
                  'banking', 'signin', 'webscr', 'ebayisapi', 'paypal']
    url_lower = url.lower()
    return 1 if any(word in url_lower for word in suspicious) else 0


# ─────────────────────────────────────────
#  Main — extract all features
# ─────────────────────────────────────────

if __name__ == '__main__':
    print("Loading datasets...")
    df = load_datasets()
    print(f"Total rows: {len(df):,}")

    print("Extracting features...")

    # existing features
    df['url_length']         = df['url'].apply(get_url_length)
    df['hostname_length']    = df['url'].apply(get_hostname_length)
    df['num_subdomains']     = df['url'].apply(get_num_subdomains)
    df['num_dots']           = df['url'].apply(get_num_dots)
    df['uses_https']         = df['url'].apply(get_uses_https)
    df['has_login_keywords'] = df['url'].apply(get_has_login_keywords)
    df['num_hyphens']        = df['url'].apply(get_num_hyphens)
    df['url_entropy']        = df['url'].apply(get_url_entropy)

    # new features
    df['path_length']           = df['url'].apply(get_path_length)
    df['num_special_chars']     = df['url'].apply(get_num_special_chars)
    df['digit_ratio']           = df['url'].apply(get_digit_ratio)
    df['has_port']              = df['url'].apply(get_has_port)
    df['has_suspicious_words']  = df['url'].apply(get_has_suspicious_words)

    df = df.drop(columns=['url'])

    output_path = 'Phishing URL dataset/features_v2.csv'
    df.to_csv(output_path, index=False)

    print(f"\nDone! Saved to {output_path}")
    print(f"Shape: {df.shape}")
    print(f"\nFeatures: {[c for c in df.columns if c != 'label']}")
    print(f"\nLabel distribution:\n{df['label'].value_counts()}")
