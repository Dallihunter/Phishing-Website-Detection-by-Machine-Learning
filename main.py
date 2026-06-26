from predict import load_artifacts, is_trusted_domain, extract_features, explain
import pandas as pd


def check_url(url: str, model, scaler) -> None:
    line = "━" * 45

    # whitelist check
    if is_trusted_domain(url):
        print(f"\n{line}")
        print(f"  ✅  LEGITIMATE")
        print(f"  Reason : trusted domain")
        print(line)
        return

    # extract & scale
    features = extract_features(url)
    X        = pd.DataFrame([features])
    X_scaled = scaler.transform(X)

    # predict
    prediction   = model.predict(X_scaled)[0]
    confidence   = model.predict_proba(X_scaled)[0]
    phishing_pct = round(confidence[1] * 100, 1)
    legit_pct    = round(confidence[0] * 100, 1)

    print(f"\n{line}")
    if prediction == 1:
        print(f"  🚨  PHISHING  —  {phishing_pct}% confidence")
        reasons = explain(features)
        if reasons:
            print(f"\n  Why:")
            for r in reasons:
                print(f"    • {r}")
    else:
        print(f"  ✅  LEGITIMATE  —  {legit_pct}% confidence")
    print(line)


def main():
    print("\n🔍 Phishing URL Detector")
    print("Type a URL to check, or 'q' to quit.\n")

    print("Loading model...", end=" ", flush=True)
    model, scaler = load_artifacts()
    print("Ready!\n")

    while True:
        url = input("Enter URL: ").strip()

        if url.lower() == 'q':
            print("Goodbye!")
            break

        if not url:
            print("Please enter a URL.\n")
            continue

        # auto-add http:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        check_url(url, model, scaler)
        print()


if __name__ == '__main__':
    main()
