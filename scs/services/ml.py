"""Behaviour anomaly detection with Isolation Forest.

Trained on synthetic 'normal' activity (no real data needed). At request time
we turn the user's last-hour activity into 6 numbers and ask how unusual it is.
The output is a percentile: 0.97 means 'more unusual than 97% of normal
behaviour seen in training'.
"""
from pathlib import Path

import joblib
import numpy as np

from scs.config import Config

MODEL_PATH = Config.INSTANCE_DIR / "iforest.joblib"
FEATURES = ["downloads_1h", "distinct_files_1h", "sensitive_1h", "mb_1h", "hour", "new_device"]
_cache = {}

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except (ImportError, Exception):
    IsolationForest = None
    SKLEARN_AVAILABLE = False


class HeuristicAnomalyDetector:
    """Fallback anomaly detector when scikit-learn C-extensions are blocked by OS policy."""

    def __init__(self):
        self.means = None
        self.stds = None

    def fit(self, X):
        self.means = np.mean(X, axis=0)
        self.stds = np.std(X, axis=0) + 1e-6
        return self

    def score_samples(self, X):
        # Higher score = more normal; lower = more anomalous
        z = (X - self.means) / self.stds
        dists = np.sqrt(np.sum(np.square(z), axis=1))
        return -dists


def synthetic_normal(n=6000, seed=42):
    rng = np.random.default_rng(seed)
    dl = 1 + rng.poisson(1.2, n)
    bulk = rng.random(n) < 0.01  # occasional legit bulk download
    dl = np.where(bulk, rng.integers(10, 22, n), dl)
    distinct = np.maximum(1, dl - rng.binomial(dl, 0.1))
    sens = rng.binomial(dl, 0.25)
    mb = dl * rng.lognormal(-1.0, 0.8, n)
    work = rng.random(n) < 0.93
    hour = np.where(work, rng.integers(8, 19, n), rng.integers(0, 24, n))
    newdev = (rng.random(n) < 0.03).astype(int)
    return np.column_stack([dl, distinct, sens, mb, hour, newdev]).astype(float)


def train(path=MODEL_PATH, seed=42):
    X = synthetic_normal(seed=seed)
    if SKLEARN_AVAILABLE and IsolationForest is not None:
        try:
            model = IsolationForest(n_estimators=200, contamination=0.02, random_state=seed).fit(X)
        except Exception:
            model = HeuristicAnomalyDetector().fit(X)
    else:
        model = HeuristicAnomalyDetector().fit(X)

    scores = np.sort(model.score_samples(X))  # higher = more normal
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "train_scores": scores}, path)
    _cache.clear()
    return model


def _load():
    if "m" not in _cache:
        if not MODEL_PATH.exists():
            train()
        try:
            _cache["m"] = joblib.load(MODEL_PATH)
        except Exception:
            # Retrain if cache or binary compatibility issues
            train()
            _cache["m"] = joblib.load(MODEL_PATH)
    return _cache["m"]


def anomaly_percentile(vec):
    """vec ordered as FEATURES -> value in [0,1]; higher = more unusual."""
    m = _load()
    s = m["model"].score_samples(np.array([vec], dtype=float))[0]
    scores = m["train_scores"]
    more_normal = len(scores) - np.searchsorted(scores, s, side="right")
    return float(more_normal / len(scores))
