import pandas as pd
from urllib.parse import urlparse
import tldextract
import re
from collections import Counter
import math


df1 = pd.read_csv('Phishing URL dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
df1 = df1.drop(columns=['Domain','URLLength','FILENAME', 'DomainLength', 'IsDomainIP', 'TLD',
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
       'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'])
df1['label'] = df1['label'].apply(lambda x: 0 if x == 1  else 1)
df1 = df1.rename(columns={'URL':'url'}) 

df2 = pd.read_csv('Phishing URL dataset/Phishing URLs.csv')
df2['label'] = df2['Type'].apply(lambda x: 1 if x == 'Phishing' else 0)
df2 = df2.drop(columns='Type') 

df3 = pd.read_csv('Phishing URL dataset/URL dataset.csv')
df3['label'] = df3['type'].apply(lambda x: 1 if x == 'phishing' else 0)
df3 = df3.drop(columns='type')

final_df = pd.concat([df1 ,df2 , df3])
# print(final_df['label'].value_counts())


def get_url_length(url):
    if pd.isna(url):
        return 0
    return len(url)

final_df['url_length'] = final_df['url'].apply(get_url_length)


def get_hostname_length(url):
    if pd.isna(url):
        return 0
    try: 
        hostname = urlparse(url).netloc
        return len(hostname)
    except:
        return 0
    
final_df['hostname_length'] = final_df['url'].apply(get_hostname_length)


def get_num_subdomains(url):
    if pd.isna(url):
        return 0 
    try:
       ext = tldextract.extract(url)
       subdomain = ext.subdomain
       if subdomain == '':
           return 0
       return subdomain.count('.') + 1
    except:
        return 0 

final_df['num_subdomains'] = final_df['url'].apply(get_num_subdomains)
# print(final_df.loc[final_df['num_subdomains'] == 19])


def get_num_dots(url):
    if pd.isna(url):
        return 0 
    try:
        return url.count('.')
    except:
        return 0
    
final_df['num_dots'] = final_df['url'].apply(get_num_dots)
# print(final_df['num_dots'].unique())


def has_at_symbol(url):
    if pd.isna(url):
        return 0 
    try:
       return 1 if '@' in url else 0
    except:
        return 0
final_df['has_at_symbol'] = final_df['url'].apply(has_at_symbol)


def get_uses_https(url):
    if pd.isna(url):
        return 0 
    try:
        return 1 if url.startswith('https://') else 0
    except:
        return 0

final_df['uses_https'] = final_df['url'].apply(get_uses_https)
# print(final_df['uses_https'].unique())


def has_login_keywords(url):
    if pd.isna(url):
        return 0 
    try:
       return 1 if 'login' in url.lower() else 0
    except:
        return 0
final_df['has_login_keywords'] = final_df['url'].apply(has_login_keywords)
# print(final_df['has_login_keywords'].unique())


def get_num_hyphens(url):
    if pd.isna(url):
        return 0
    try:
        return url.count('-')  # یا hostname فقط: urlparse(url).netloc.count('-')
    except:
        return 0

final_df['num_hyphens'] = final_df['url'].apply(get_num_hyphens)


def has_ip_address(url):
    if pd.isna(url):
        return 0
    try:
        hostname = urlparse(url).netloc
        # regex برای IPv4
        ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
        return 1 if re.match(ip_pattern, hostname) else 0
    except:
        return 0

final_df['has_ip_address'] = final_df['url'].apply(has_ip_address)

def get_url_entropy(url):
    if pd.isna(url) or url == '':
        return 0
    try:
        counts = Counter(url)
        total = len(url)
        entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
        return entropy
    except:
        return 0 

final_df['url_entropy'] = final_df['url'].apply(get_url_entropy)


print(final_df)
