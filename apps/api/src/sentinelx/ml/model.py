"""Isolation Forest behavioral baseline with calibrated scores and per-feature explanations.

* Features are log1p-transformed counts per host-hour (heavy-tailed telemetry -> log scale).
* ``anomaly_score`` is an equal-weight ensemble of two interpretable parts:
  - the percentile rank of the window's isolation score among training windows (multivariate rarity), and
  - a directional deviation score ``1 - exp(-(z_max - 2) / 3)`` from the largest robust z-score of any
    feature *above* its baseline (only increases count: unusually quiet hours are rare but not a threat).
  The ensemble is far more stable than the isolation percentile alone on small baselines.
* A window is flagged when the ensemble score is high *and* some feature is >= 4 robust σ above normal.
* Explanations use robust z-scores (median / MAD) of each feature against the training baseline;
  they explain *which behaviour changed*, independent of tree internals.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_NAME = "isolation_forest"
MODEL_VERSION_TAG = "isolation_forest_v1"


@dataclass
class TrainedModel:
    forest: IsolationForest
    feature_names: list[str]
    median: np.ndarray
    mad: np.ndarray
    train_scores: np.ndarray  # sorted raw scores (higher = more anomalous)

    def to_bytes(self) -> bytes:
        buf = io.BytesIO()
        joblib.dump(
            {
                "forest": self.forest,
                "feature_names": self.feature_names,
                "median": self.median,
                "mad": self.mad,
                "train_scores": self.train_scores,
            },
            buf,
        )
        return buf.getvalue()

    @classmethod
    def from_bytes(cls, data: bytes) -> TrainedModel:
        # Artifacts are produced by SentinelX itself and stored in its own database (never user uploads).
        obj = joblib.load(io.BytesIO(data))
        return cls(**obj)


def _transform(x: np.ndarray) -> np.ndarray:
    return np.log1p(np.clip(x, 0, None))


def train(x: np.ndarray, feature_names: list[str], seed: int = 42) -> TrainedModel:
    if x.shape[0] < 24:
        raise ValueError("not enough baseline windows to train (need at least 24 host-hours)")
    xt = _transform(x)
    forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=1)
    forest.fit(xt)
    median = np.median(xt, axis=0)
    mad = np.median(np.abs(xt - median), axis=0)
    scores = np.sort(-forest.score_samples(xt))
    return TrainedModel(forest, feature_names, median, mad, scores)


def deviation_score(z: np.ndarray) -> np.ndarray:
    top = np.clip(z.max(axis=1), 0, None) if z.ndim == 2 else np.array([max(0.0, float(z.max()))])
    return 1.0 - np.exp(-np.clip(top - 2.0, 0, None) / 3.0)


def score(model: TrainedModel, x: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Returns (ensemble anomaly score 0..1, raw isolation score, robust z matrix)."""
    xt = _transform(x)
    raw = -model.forest.score_samples(xt)
    percentile = np.searchsorted(model.train_scores, raw, side="right") / max(1, len(model.train_scores))
    # MAD is 0 for sparse features (usually-zero counts); a floor of 0.5 (log scale) keeps a jump from 0 to a
    # handful (e.g. 3 failed logins) modest while a jump to dozens still stands out strongly.
    scale = np.maximum(1.4826 * model.mad, 0.5)
    z = (xt - model.median) / scale
    return 0.5 * percentile + 0.5 * deviation_score(z), raw, z


def explain(model: TrainedModel, xrow: np.ndarray, zrow: np.ndarray, top: int = 4) -> list[dict[str, Any]]:
    order = np.argsort(-zrow)
    out = []
    for i in order[:top]:
        if zrow[i] <= 1.0:
            break
        out.append(
            {
                "feature": model.feature_names[i],
                "value": float(xrow[i]),
                "baseline_median": float(np.expm1(model.median[i])),
                "z_score": round(float(zrow[i]), 2),
                "direction": "higher than usual",
            }
        )
    return out


def evaluate(model: TrainedModel, normal: np.ndarray, abnormal: np.ndarray) -> dict[str, float]:
    """Controlled evaluation: abnormal windows should outscore normal ones (ROC-AUC style ranking)."""
    n, _, _ = score(model, normal)
    a, _, _ = score(model, abnormal)
    wins = sum(float(np.sum(ai > n)) + 0.5 * float(np.sum(ai == n)) for ai in a)
    auc = wins / max(1, len(a) * len(n))
    return {"auc": round(auc, 4), "mean_normal": round(float(n.mean()), 4), "mean_abnormal": round(float(a.mean()), 4)}
