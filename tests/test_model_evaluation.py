"""
Layer 2: Model evaluation regression tests.

These reproduce the exact train/test split used in train_model.py
(same random_state=42, same stratify, same test_size=0.2) so the
"test" portion here is the same held-out data your model has never
seen. The point isn't to re-measure accuracy for fun — it's a
tripwire: if a future change to features.py, the whitelist, or
retraining parameters quietly tanks recall or accuracy, these tests
fail instead of the regression shipping unnoticed.

Baseline thresholds below are set slightly under your documented
v1.1.1 numbers (96.7% accuracy / 93.2% recall) to leave headroom for
normal retraining variance, while still catching real regressions.
Tighten these once you're confident in the numbers after the
feature-drift fix retrain.
"""

import pytest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Regression floors — update these deliberately when you intentionally
# retrain to a new, verified baseline. Never loosen them just to make
# a failing test pass.
MIN_ACCURACY = 0.94
MIN_RECALL = 0.90
MIN_PRECISION = 0.90


@pytest.fixture(scope="module")
def held_out_split(features_dataframe):
    df = features_dataframe
    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    return X_test, y_test


@pytest.fixture(scope="module")
def predictions(model_and_scaler, held_out_split):
    model, scaler = model_and_scaler
    X_test, y_test = held_out_split
    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    return y_test, y_pred


def test_accuracy_meets_floor(predictions):
    y_test, y_pred = predictions
    acc = accuracy_score(y_test, y_pred)
    assert acc >= MIN_ACCURACY, f"accuracy {acc:.4f} fell below floor {MIN_ACCURACY}"


def test_recall_meets_floor(predictions):
    """
    Recall is the priority metric per your project's stated principle:
    missing a real phishing URL is worse than a false alarm.
    """
    y_test, y_pred = predictions
    rec = recall_score(y_test, y_pred)
    assert rec >= MIN_RECALL, f"recall {rec:.4f} fell below floor {MIN_RECALL}"


def test_precision_meets_floor(predictions):
    y_test, y_pred = predictions
    prec = precision_score(y_test, y_pred)
    assert prec >= MIN_PRECISION, f"precision {prec:.4f} fell below floor {MIN_PRECISION}"


def test_model_is_not_predicting_a_single_class(predictions):
    """Sanity check against a degenerate model that always predicts one label."""
    _, y_pred = predictions
    assert len(set(y_pred)) > 1, "model predicted only one class on the entire test set"


def test_print_current_metrics(predictions, capsys):
    """
    Not an assertion — just surfaces the current numbers in pytest -s
    output so you always see where the model actually stands, not just
    pass/fail against the floor.
    """
    y_test, y_pred = predictions
    print(f"\n  Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"  Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"  Recall   : {recall_score(y_test, y_pred):.4f}")
    print(f"  F1       : {f1_score(y_test, y_pred):.4f}")
    
