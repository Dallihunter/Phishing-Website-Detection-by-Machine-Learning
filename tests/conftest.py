"""
Shared fixtures for the test suite.

Model/scaler and the training CSV are generated artifacts (not in the
repo, per your .gitignore policy), so fixtures that need them use
pytest.skip() when missing instead of failing — this lets
`pytest tests/test_features.py` run fine on a fresh clone even before
you've downloaded data or trained anything, while
`pytest tests/test_model_evaluation.py` only runs where it can.
"""

import os
import sys
import pytest

# Make the project root importable when running `pytest` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_PATH = "rf_phishing_model.pkl"
SCALER_PATH = "scaler.pkl"
FEATURES_CSV_PATH = "Phishing URL dataset/features_v2.csv"


@pytest.fixture(scope="session")
def model_and_scaler():
    if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)):
        pytest.skip(
            f"{MODEL_PATH} / {SCALER_PATH} not found — run train_model.py first"
        )
    from predict import load_artifacts
    return load_artifacts()


@pytest.fixture(scope="session")
def features_dataframe():
    if not os.path.exists(FEATURES_CSV_PATH):
        pytest.skip(
            f"{FEATURES_CSV_PATH} not found — run feature_extractor.py first"
        )
    import pandas as pd
    return pd.read_csv(FEATURES_CSV_PATH)
