import pandas as pd
import numpy as np

def load_and_clean(path='Phishing URL dataset/features.csv'):
    df = pd.read_csv(path)
    
    # حذف ستون index اضافه
    df = df.drop(columns=['Unnamed: 0'])
    
    # clip کردن outlier ها با مرز 99th percentile
    clip_cols = ['url_length', 'hostname_length', 'num_subdomains',
                 'num_dots', 'num_hyphens', 'url_entropy']
    
    for col in clip_cols:
        upper = df[col].quantile(0.99)
        df[col] = df[col].clip(upper=upper)
    
    return df

if __name__ == '__main__':
    df = load_and_clean()
    
    print("=== After Preprocessing ===")
    print(f"Shape: {df.shape}")
    print(f"\nLabel distribution:\n{df['label'].value_counts()}")
    print(f"\nDescribe after clip:")
    print(df[['url_length','hostname_length','num_hyphens']].describe().round(2))
    
    df.to_csv('Phishing URL dataset/features_clean.csv', index=False)
    print("\nfeatures_clean.csv saved!")
