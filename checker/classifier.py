"""Optional text classifier (TF-IDF + logistic regression), trained on YOUR labeled data.

Needs scikit-learn. Only `scam` and `legit` rows are used; `unclear` rows are skipped.
The model is small and is meant to be compared against the rules, not to replace them.
"""
from __future__ import annotations

import pickle
from pathlib import Path


class NotEnoughData(Exception):
    pass


def available() -> bool:
    try:
        import sklearn  # noqa: F401
        return True
    except ImportError:
        return False


def train(texts: list[str], labels: list[str], min_per_class: int = 5):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline

    pairs = [(t, l) for t, l in zip(texts, labels) if l in ("scam", "legit")]
    counts = {c: sum(1 for _, l in pairs if l == c) for c in ("scam", "legit")}
    if min(counts.values()) < min_per_class:
        raise NotEnoughData(f"need at least {min_per_class} scam and {min_per_class} legit rows, have {counts}")
    X, y = [t for t, _ in pairs], [1 if l == "scam" else 0 for _, l in pairs]
    model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, lowercase=True),
                          LogisticRegression(class_weight="balanced", max_iter=1000))
    model.fit(X, y)
    return model


def predict_proba(model, text: str) -> float:
    return float(model.predict_proba([text])[0][1])


def save(model, path: Path) -> None:
    with open(path, "wb") as fh:
        pickle.dump(model, fh)


def load(path: Path):
    # Only load a model file you trained yourself: pickle can run code from untrusted files.
    with open(path, "rb") as fh:
        return pickle.load(fh)
